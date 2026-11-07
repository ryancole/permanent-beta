//! `pbeta` CLI. Thin layer: argument parsing, file I/O, output formatting, exit codes.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_analysis::{
    Analyzer, diff, export, ghidra,
    native::{NativePeAnalyzer, pattern::PatternIndex},
    symbols,
};
use permanent_beta_engine::Engine;
use permanent_beta_engine::permanent_beta_repair::{HookRepair, RepairAction};
use permanent_beta_engine::permanent_beta_verify::{
    TraceDiffRunner,
    behavioral::{self, HookOutcome, TraceDiff},
};
use permanent_beta_model::{
    BuildId, CandidateSource, Criticality, DecisionAction, HookManifest, PriorDecisions,
    ReviewStatus, Rva, Trace, TraceEvent, Verdict,
};
use permanent_beta_store::{Choice, JsonFileStore, MappingStore};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EXIT_OK: u8 = 0;
const EXIT_NEEDS_REVIEW: u8 = 1;
const EXIT_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "pbeta",
    version,
    about = "Map functions across binary versions and repair instrumentation hooks"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze a PE x64 binary into the normalized AnalysisExport JSON (native analyzer).
    Analyze {
        binary: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// The build's PDB: add its function names and signatures. Refused unless its GUID and age match the
        /// binary's debug directory. Boundaries and hashes stay the native analyzer's.
        #[arg(long)]
        pdb: Option<PathBuf>,
        /// With --pdb, also write the PDB's procedures (entry, length, name, signature) as an analysis, for
        /// comparing function boundaries with `pbeta analysis-diff`.
        #[arg(long, requires = "pdb")]
        pdb_functions: Option<PathBuf>,
        /// Take function boundaries from a Ghidra export (integrations/ghidra/scripts/ExportFunctions.java)
        /// instead of native discovery. Hashes and features are still computed natively. Refused unless the
        /// export is of this file.
        #[arg(long)]
        functions_from: Option<PathBuf>,
    },
    /// Compare two analyses of the same build: functions only one found, different sizes, hashes or names.
    /// Exit code 1 if they disagree at all.
    AnalysisDiff {
        a: PathBuf,
        b: PathBuf,
        /// Print the full report as JSON.
        #[arg(long)]
        json: bool,
        /// List at most this many functions per kind of disagreement (text output).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Match functions between two analysis exports and verify each candidate.
    Match {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// Print the full report as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Repair a hook manifest against a new build. Exit code 1 if any hook needs review.
    Repair {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// Hook manifest (TOML).
        #[arg(long)]
        hooks: PathBuf,
        /// Analysis of an older build that some hooks are still bound to (an earlier repair sent them to
        /// review). Those hooks are repaired from that build directly. Repeatable.
        #[arg(long)]
        earlier: Vec<PathBuf>,
        /// Write the repaired manifest here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// The new binary: regenerate a unique AOB pattern for every re-bound hook. Without it, re-bound hooks
        /// carry no pattern (the old one was only checked against the old build).
        #[arg(long)]
        new_binary: Option<PathBuf>,
        /// Write a trial manifest here: the repaired manifest plus trial bindings for hooks in review whose only
        /// missing evidence is behavioral. Run the new build under it and pass that trace as --new-trace.
        #[arg(long)]
        trial_out: Option<PathBuf>,
        /// Record accepted mappings and review items in this store, and honor its review decisions.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Behavioral evidence (design §7.3): a scenario trace of an old build with hooks at the old RVAs (the
        /// previous build's, and any --earlier build's). Each candidate is judged against its own build's run.
        /// Repeatable; needs --new-trace.
        #[arg(long, requires = "new_trace")]
        old_trace: Vec<PathBuf>,
        /// The same scenario on the new build with hooks at the candidates' RVAs (e.g. the --trial-out run).
        #[arg(long, requires = "old_trace")]
        new_trace: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Compare scenario call traces hook by hook (design §7.3). Exit code 1 if any hook's behavior differs, a
    /// hook didn't fire or wasn't attached, the run crashed, or a hook sent to review was applied anyway.
    TraceDiff {
        /// Trace of the old build with the original hooks. Repeatable, most recent first: each hook is compared
        /// with the first run that applied it (a hook repaired from an older build, with that build's run).
        #[arg(
            long,
            conflicts_with = "baseline",
            required_unless_present = "baseline"
        )]
        old: Vec<PathBuf>,
        /// Trace of the new build with the repaired hooks.
        #[arg(long, requires = "old")]
        new: Option<PathBuf>,
        /// Check a single baseline trace instead: every hook must attach and fire.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// The manifest the (new) run used.
        #[arg(long)]
        hooks: PathBuf,
        /// `pbeta repair --json` output for this step: hooks it sent to review must be held, and every hook
        /// that wasn't attached must be one of them.
        #[arg(long, conflicts_with = "baseline")]
        repair: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Print the shortest unique AOB pattern for the function at an RVA (design §7.2).
    Pattern {
        binary: PathBuf,
        #[arg(long)]
        rva: Rva,
    },
    /// Generate the offsets header (`hooks.gen.h`): each build's hook RVAs and patterns, from hook manifests.
    Header {
        /// Hook manifests, e.g. every repaired manifest of a release line. Repeatable.
        #[arg(long, required = true)]
        hooks: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ask an AI model about functions matching left unmatched (design §8). Each proposal is verified like any
    /// candidate and queued for review (`--store`); none is ever accepted. Exit code 1 if any were queued.
    Propose {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// Queue proposals in this store's review queue. Without it they're only printed.
        #[arg(long)]
        store: Option<PathBuf>,
        /// Only these old functions (default: every unmatched one). Repeatable.
        #[arg(long)]
        rva: Vec<Rva>,
        /// Ask about at most this many functions.
        #[arg(long)]
        limit: Option<usize>,
        /// Claude model id.
        #[arg(long, default_value = "claude-opus-5-5")]
        model: String,
        #[arg(long)]
        effort: Option<String>,
        /// The Claude Code CLI (it runs on your Claude subscription after `/login`).
        #[arg(long, env = "PBETA_CLAUDE", default_value = "claude")]
        claude: PathBuf,
        /// Every exchange with the model, prompt and reply, is appended here, and recorded answers are replayed
        /// from it.
        #[arg(long, default_value = ".pbeta/ai-log.jsonl")]
        log: PathBuf,
        /// Claude is a remote model: function features (strings included) leave this machine. Required to ask
        /// it (design §8: remote providers are opt-in and logged).
        #[arg(long)]
        allow_remote: bool,
        /// Only use answers already recorded in --log; never call the model.
        #[arg(long, conflicts_with = "allow_remote")]
        replay: bool,
        /// Candidates shown per question.
        #[arg(long, default_value_t = permanent_beta_ai::shortlist::SHORTLIST_LEN)]
        shortlist: usize,
        #[arg(long)]
        json: bool,
    },
    /// Inspect and decide the review queue.
    Review {
        #[command(subcommand)]
        command: ReviewCommand,
    },
}

#[derive(Subcommand)]
enum ReviewCommand {
    /// List open review items with their candidates. Exit code 1 if any are open.
    List {
        #[arg(long, default_value = ".pbeta/store.json")]
        store: PathBuf,
        /// Include resolved items.
        #[arg(long)]
        all: bool,
    },
    /// Accept a candidate as the hook target's counterpart. The next `repair --store` uses it.
    Accept {
        /// Review item id, as `review list` prints it.
        id: String,
        /// Which candidate (new-build RVA). Required when the item has more than one.
        #[arg(long)]
        candidate: Option<Rva>,
        /// Who decided. Recorded with the decision and the mapping.
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        note: Option<String>,
        /// Accept even a candidate that verification rejected.
        #[arg(long)]
        force: bool,
        #[arg(long, default_value = ".pbeta/store.json")]
        store: PathBuf,
    },
    /// Reject every candidate of an item: none is the counterpart. They're never proposed for it again.
    Reject {
        id: String,
        #[arg(long)]
        reviewer: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long, default_value = ".pbeta/store.json")]
        store: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(cli: Cli) -> Result<u8> {
    match cli.command {
        Command::Analyze {
            binary,
            out,
            pdb,
            pdb_functions,
            functions_from,
        } => cmd_analyze(
            &binary,
            &out,
            pdb.as_deref(),
            pdb_functions.as_deref(),
            functions_from.as_deref(),
        ),
        Command::AnalysisDiff { a, b, json, limit } => cmd_analysis_diff(&a, &b, json, limit),
        Command::Match { old, new, json } => cmd_match(&old, &new, json),
        Command::Repair {
            old,
            new,
            hooks,
            earlier,
            out,
            new_binary,
            trial_out,
            store,
            old_trace,
            new_trace,
            json,
        } => {
            let traces = match new_trace {
                Some(n) => Some((
                    old_trace
                        .iter()
                        .map(|p| load_trace(p))
                        .collect::<Result<Vec<_>>>()?,
                    load_trace(&n)?,
                )),
                None => None,
            };
            cmd_repair(RepairArgs {
                old: &old,
                new: &new,
                hooks: &hooks,
                earlier: &earlier,
                out: out.as_deref(),
                new_binary: new_binary.as_deref(),
                trial_out: trial_out.as_deref(),
                store: store.as_deref(),
                traces,
                json,
            })
        }
        Command::Pattern { binary, rva } => cmd_pattern(&binary, rva),
        Command::Propose {
            old,
            new,
            store,
            rva,
            limit,
            model,
            effort,
            claude,
            log,
            allow_remote,
            replay,
            shortlist,
            json,
        } => {
            anyhow::ensure!(
                allow_remote || replay,
                "Claude is a remote model: function features, strings included, would leave this machine. Pass \
                 --allow-remote to ask it (every exchange is logged to {}), or --replay to use recorded answers",
                log.display()
            );
            let live: Option<Box<dyn permanent_beta_ai::backend::Model>> = (!replay).then(|| {
                Box::new(permanent_beta_ai::backend::ClaudeCode {
                    program: claude,
                    model: model.clone(),
                    effort,
                }) as Box<dyn permanent_beta_ai::backend::Model>
            });
            let backend = permanent_beta_ai::backend::Cassette::open(
                &log,
                &format!("claude-code:{model}"),
                live,
            )
            .map_err(anyhow::Error::msg)?;
            cmd_propose(ProposeArgs {
                old: &old,
                new: &new,
                store: store.as_deref(),
                only: &rva,
                limit,
                shortlist,
                model: &backend,
                json,
            })
        }
        Command::Header { hooks, out } => cmd_header(&hooks, &out),
        Command::TraceDiff {
            old,
            new,
            baseline,
            hooks,
            repair,
            json,
        } => cmd_trace_diff(
            &old,
            new.as_deref(),
            baseline.as_deref(),
            &hooks,
            repair.as_deref(),
            json,
        ),
        Command::Review { command } => match command {
            ReviewCommand::List { store, all } => cmd_review_list(&store, all),
            ReviewCommand::Accept {
                id,
                candidate,
                reviewer,
                note,
                force,
                store,
            } => cmd_review_decide(
                &store,
                &id,
                &reviewer,
                Choice::Accept { candidate, force },
                note,
            ),
            ReviewCommand::Reject {
                id,
                reviewer,
                note,
                store,
            } => cmd_review_decide(&store, &id, &reviewer, Choice::Reject, note),
        },
    }
}

fn cmd_match(old: &Path, new: &Path, json: bool) -> Result<u8> {
    let (old, new) = (export::load(old)?, export::load(new)?);
    let report = Engine::with_defaults().match_builds(&old, &new);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(EXIT_OK);
    }
    println!("{:<10} {:<10} {:<14} matched by", "old", "new", "verdict");
    for r in &report.reports {
        println!(
            "{:<10} {:<10} {:<14} {}",
            r.candidate.old.to_string(),
            r.candidate.new.to_string(),
            verdict_str(r.verdict),
            source_str(&r.candidate.source)
        );
    }
    for a in &report.ambiguities {
        let list = |rvas: &[permanent_beta_model::Rva]| {
            rvas.iter()
                .map(|r| r.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{:<10} {:<10} {:<14} {} ({})",
            list(&a.old),
            list(&a.new),
            "ambiguous",
            a.matcher,
            a.detail
        );
    }
    println!(
        "\n{} candidates, {} ambiguous groups; {} old and {} new functions unmatched",
        report.reports.len(),
        report.ambiguities.len(),
        report.unmatched_old.len(),
        report.unmatched_new.len()
    );
    Ok(EXIT_OK)
}

struct RepairArgs<'a> {
    old: &'a Path,
    new: &'a Path,
    hooks: &'a Path,
    earlier: &'a [PathBuf],
    out: Option<&'a Path>,
    new_binary: Option<&'a Path>,
    trial_out: Option<&'a Path>,
    store: Option<&'a Path>,
    traces: Option<(Vec<Trace>, Trace)>,
    json: bool,
}

fn cmd_repair(a: RepairArgs) -> Result<u8> {
    let (old, new) = (export::load(a.old)?, export::load(a.new)?);
    let earlier = a
        .earlier
        .iter()
        .map(|p| export::load(p).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    let manifest = load_manifest(a.hooks)?;
    permanent_beta_engine::permanent_beta_repair::check_input(&manifest)
        .map_err(|e| anyhow::anyhow!("{}: {e}", a.hooks.display()))?;

    let mut opened = a.store.map(JsonFileStore::open).transpose()?;
    let priors: BTreeMap<BuildId, PriorDecisions> = opened
        .as_ref()
        .map(|s| {
            std::iter::once(&old)
                .chain(&earlier)
                .map(|e| {
                    (
                        e.build.id.clone(),
                        s.prior_decisions(&e.build.id, &new.build.id),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let engine = match a.traces {
        Some((o, n)) => Engine::with_behavioral(Box::new(TraceDiffRunner::with_baselines(o, n))),
        None => Engine::with_defaults(),
    };
    let mut report = engine.repair_across(&manifest, &old, &earlier, &new, &priors);

    // AOB patterns for re-bound hooks, from the new binary (rewrite_manifest dropped the old ones).
    let mut pattern_notes: Vec<String> = Vec::new();
    if let Some(bin) = a.new_binary {
        let bytes = std::fs::read(bin).with_context(|| format!("reading {}", bin.display()))?;
        let index = PatternIndex::new(&bytes)
            .map_err(|e| anyhow::anyhow!("{}: not a PE x64 image: {e}", bin.display()))?;
        let binary_build = permanent_beta_analysis::native::build_id(&bytes);
        anyhow::ensure!(
            binary_build == new.build.id,
            "{} is build {}, but --new is an analysis of {}",
            bin.display(),
            binary_build.0,
            new.build.id.0
        );
        for hook in &mut report.updated_manifest.hooks {
            let rebound = report
                .repairs
                .iter()
                .any(|r| r.hook == hook.name && r.is_resolved());
            let Some(rva) = hook.target.rva.filter(|_| rebound) else {
                continue;
            };
            match index.generate(rva.0) {
                Ok(p) => hook.target.pattern = Some(p.to_string()),
                Err(e) => pattern_notes.push(format!("{}: no pattern at {rva} ({e})", hook.name)),
            }
        }
    }

    if let Some(out) = a.out {
        std::fs::write(out, toml::to_string_pretty(&report.updated_manifest)?)
            .with_context(|| format!("writing {}", out.display()))?;
    }
    let mut trialed = Vec::new();
    if let Some(path) = a.trial_out {
        let (trial, names) = permanent_beta_engine::permanent_beta_repair::trial_manifest(
            &report.updated_manifest,
            &report.repairs,
            &new,
        );
        let text = format!(
            "# TRIAL MANIFEST: hooks marked `trial = true` are bound to unverified review candidates, for a test \
             run that\n# collects behavioral evidence (pbeta repair --new-trace). Never ship it; pbeta repair \
             refuses it as input.\n{}",
            toml::to_string_pretty(&trial)?
        );
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        trialed = names;
    }
    if let Some(store) = opened.as_mut() {
        store.put_mappings(&report.mappings)?;
        store.enqueue_review(&report.review_items)?;
    }

    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for r in &report.repairs {
            let by = r
                .reviewed_by
                .as_ref()
                .map(|who| format!(" (decided by {who})"))
                .unwrap_or_default();
            let from = r
                .from_build
                .as_ref()
                .map(|b| format!(" [from build {}]", b.0.get(..12).unwrap_or(&b.0)))
                .unwrap_or_default();
            let outcome = match &r.action {
                RepairAction::Unchanged { rva } => format!("unchanged at {rva}{by}{from}"),
                RepairAction::Relocated { old, new } => {
                    format!("relocated {old} -> {new}{by}{from}")
                }
                RepairAction::NeedsReview { reason, detail } => {
                    format!(
                        "NEEDS REVIEW ({}){from}: {detail}",
                        serde_json::to_value(reason)?.as_str().unwrap_or("?")
                    )
                }
            };
            println!("{:<18} {outcome}", r.hook);
            for p in &r.proposals {
                println!(
                    "{:<18}   proposed prototype for {}: {}",
                    "", p.candidate, p.prototype
                );
            }
        }
        let resolved = report.repairs.iter().filter(|r| r.is_resolved()).count();
        println!("\n{resolved}/{} hooks resolved", report.repairs.len());
        for n in &pattern_notes {
            println!("pattern: {n}");
        }
        if let Some(out) = a.out {
            println!("repaired manifest written to {}", out.display());
        }
        if let Some(path) = a.trial_out {
            println!(
                "trial manifest written to {} (trial bindings: {})",
                path.display(),
                if trialed.is_empty() {
                    "none".to_owned()
                } else {
                    trialed.join(", ")
                }
            );
        }
    }
    Ok(if report.needs_review() {
        EXIT_NEEDS_REVIEW
    } else {
        EXIT_OK
    })
}

struct ProposeArgs<'a> {
    old: &'a Path,
    new: &'a Path,
    store: Option<&'a Path>,
    only: &'a [Rva],
    limit: Option<usize>,
    shortlist: usize,
    model: &'a dyn permanent_beta_ai::backend::Model,
    json: bool,
}

fn cmd_propose(a: ProposeArgs) -> Result<u8> {
    use permanent_beta_ai::{Outcome, Proposer, shortlist::Matched};
    let (old, new) = (export::load(a.old)?, export::load(a.new)?);
    let engine = Engine::with_defaults();
    let report = engine.match_builds(&old, &new);
    let pairs: Vec<_> = report.reports.iter().map(|r| r.candidate.clone()).collect();
    let targets: Vec<Rva> = if a.only.is_empty() {
        report.unmatched_old.clone()
    } else {
        a.only.to_vec()
    };
    let targets = &targets[..a.limit.unwrap_or(usize::MAX).min(targets.len())];

    let mut proposer = Proposer::new(a.model);
    proposer.shortlist_len = a.shortlist;
    let m = Matched::new(&old, &new, &pairs);
    let mut rows = Vec::new();
    let mut items = Vec::new();
    for &rva in targets {
        let asked = proposer.ask_with(&m, &old, &new, rva);
        // Every proposal goes through the engine's verification, then to review: never accepted here.
        let verified = match &asked.outcome {
            Outcome::Proposed { candidate } => {
                engine.verify_candidate(&old, &new, candidate, Criticality::Normal)
            }
            _ => None,
        };
        if let Some(v) = &verified {
            items.push(
                permanent_beta_engine::permanent_beta_repair::proposal_review_item(
                    v,
                    &old.build.id,
                    &new.build.id,
                ),
            );
        }
        rows.push((asked, verified));
    }
    if let Some(path) = a.store {
        JsonFileStore::open(path)?.enqueue_review(&items)?;
    }

    if a.json {
        let out: Vec<_> = rows
            .iter()
            .map(|(asked, v)| serde_json::json!({ "asked": asked, "verification": v }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        for (asked, v) in &rows {
            let what = match (&asked.outcome, v) {
                (Outcome::Proposed { candidate }, Some(v)) => format!(
                    "proposed {} (confidence {:.2}); verification: {}",
                    candidate.new,
                    candidate.score,
                    verdict_str(v.verdict)
                ),
                (Outcome::Proposed { candidate }, None) => {
                    format!("proposed {} (couldn't be verified)", candidate.new)
                }
                (Outcome::Abstained { confidence, .. }, _) => {
                    format!(
                        "none of {} candidates (confidence {confidence:.2})",
                        asked.shortlist.len()
                    )
                }
                (Outcome::NoShortlist, _) => "no unmatched function close enough to ask".into(),
                (Outcome::Failed { error }, _) => format!("FAILED: {error}"),
            };
            println!("{:<10} {what}", asked.old.to_string());
        }
        println!(
            "\n{} asked, {} proposals{}",
            rows.len(),
            items.len(),
            match a.store {
                Some(p) => format!(
                    " queued for review in {} (decide with `pbeta review`)",
                    p.display()
                ),
                None => " (not queued: no --store)".into(),
            }
        );
    }
    Ok(if items.is_empty() {
        EXIT_OK
    } else {
        EXIT_NEEDS_REVIEW
    })
}

fn cmd_analyze(
    binary: &Path,
    out: &Path,
    pdb: Option<&Path>,
    pdb_functions: Option<&Path>,
    functions_from: Option<&Path>,
) -> Result<u8> {
    let mut analysis = match functions_from {
        None => NativePeAnalyzer.analyze(binary)?,
        Some(path) => {
            let bytes =
                std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
            let file_name = binary
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let (analysis, r) = ghidra::analyze(&bytes, &file_name, &ghidra::load(path)?)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
            eprintln!(
                "Ghidra: {} functions, {} analyzed; {} outside code, {} duplicate entries; names ignored {}; signatures used {}, ignored {}; pseudocode {}",
                r.exported,
                r.analyzed,
                r.outside_code.len(),
                r.duplicates,
                r.names_ignored,
                r.signatures_used,
                r.signatures_inferred,
                r.with_pseudocode
            );
            analysis
        }
    };
    if let Some(pdb) = pdb {
        let symbols = symbols::read(pdb)?;
        let report = symbols::apply(&mut analysis, &symbols)
            .map_err(|e| anyhow::anyhow!("{}: {e}", pdb.display()))?;
        eprintln!(
            "PDB: {} entries; named {}, signed {}, {} folded (left unnamed), {} not found by the native analyzer",
            report.pdb_entries,
            report.named,
            report.signed,
            report.ambiguous,
            report.not_in_analysis
        );
        if let Some(path) = pdb_functions {
            export::save(&symbols::procedures_export(&analysis.build, &symbols), path)?;
        }
    }
    export::save(&analysis, out)?;
    Ok(EXIT_OK)
}

fn cmd_analysis_diff(a: &Path, b: &Path, json: bool, limit: usize) -> Result<u8> {
    let d = diff::diff(&export::load(a)?, &export::load(b)?);
    if json {
        println!("{}", serde_json::to_string_pretty(&d)?);
    } else {
        print_analysis_diff(&d, limit);
    }
    Ok(if d.is_clean() {
        EXIT_OK
    } else {
        EXIT_NEEDS_REVIEW
    })
}

fn print_analysis_diff(d: &diff::AnalysisDiff, limit: usize) {
    println!("a: {} ({} functions)", d.a_producer, d.a_functions);
    println!("b: {} ({} functions)", d.b_producer, d.b_functions);
    if d.different_builds {
        println!(
            "DIFFERENT BUILDS: RVAs aren't comparable; the rest of this report is meaningless"
        );
    }
    println!(
        "agree {} · only a {} · only b {} · size differs {} · hash differs {} · name differs {}",
        d.agreeing,
        d.only_a.len(),
        d.only_b.len(),
        d.size_differs.len(),
        d.hash_differs.len(),
        d.name_differs.len()
    );
    let name = |n: &Option<String>| n.as_deref().map(|n| format!(" {n}")).unwrap_or_default();
    let section = |title: &str, lines: Vec<String>| {
        if lines.is_empty() {
            return;
        }
        println!(
            "
{title}:"
        );
        for l in lines.iter().take(limit) {
            println!("  {l}");
        }
        if lines.len() > limit {
            println!("  ... {} more (--limit, --json)", lines.len() - limit);
        }
    };
    let unpaired = |u: &diff::Unpaired| {
        let inside = u
            .inside
            .map(|r| format!(", inside the other's {r}"))
            .unwrap_or_default();
        format!("{}{} ({} bytes{inside})", u.rva, name(&u.name), u.size)
    };
    section("only in a", d.only_a.iter().map(unpaired).collect());
    section("only in b", d.only_b.iter().map(unpaired).collect());
    section(
        "size differs",
        d.size_differs
            .iter()
            .map(|s| {
                format!(
                    "{}{}: {} vs {} bytes",
                    s.rva,
                    name(&s.name),
                    s.a_size,
                    s.b_size
                )
            })
            .collect(),
    );
    section(
        "hash differs",
        d.hash_differs
            .iter()
            .map(|h| format!("{}{}: {:?}", h.rva, name(&h.name), h.kind))
            .collect(),
    );
    section(
        "name differs",
        d.name_differs
            .iter()
            .map(|n| format!("{}: {} vs {}", n.rva, n.a_name, n.b_name))
            .collect(),
    );
}

fn cmd_pattern(binary: &Path, rva: Rva) -> Result<u8> {
    let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let index = PatternIndex::new(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: not a PE x64 image: {e}", binary.display()))?;
    match index.generate(rva.0) {
        Ok(p) => {
            println!("{p}");
            Ok(EXIT_OK)
        }
        Err(e) => {
            eprintln!("{rva}: {e}");
            Ok(EXIT_NEEDS_REVIEW)
        }
    }
}

fn cmd_header(hooks: &[PathBuf], out: &Path) -> Result<u8> {
    let manifests = hooks
        .iter()
        .map(|p| load_manifest(p))
        .collect::<Result<Vec<_>>>()?;
    let text = permanent_beta_engine::permanent_beta_repair::header::offsets_header(&manifests)
        .map_err(|e| anyhow::anyhow!(e))?;
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    println!("offsets header written to {}", out.display());
    Ok(EXIT_OK)
}

fn load_manifest(path: &Path) -> Result<HookManifest> {
    toml::from_str(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .with_context(|| format!("parsing hook manifest {}", path.display()))
}

/// A JSON Lines trace (one `TraceEvent` per line) as the harness DLL writes it.
fn load_trace(path: &Path) -> Result<Trace> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let events = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str::<TraceEvent>(l)
                .with_context(|| format!("{} line {}", path.display(), i + 1))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Trace { events })
}

/// Hooks `pbeta repair --json` sent to review, with their reasons.
fn held_for_review(path: &Path) -> Result<BTreeMap<String, String>> {
    #[derive(serde::Deserialize)]
    struct Report {
        repairs: Vec<HookRepair>,
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let report: Report = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("parsing repair report {}", path.display()))?;
    report
        .repairs
        .into_iter()
        .filter_map(|r| match r.action {
            RepairAction::NeedsReview { reason, .. } => Some((r.hook, reason)),
            _ => None,
        })
        .map(|(hook, reason)| {
            let reason = serde_json::to_value(reason)?;
            Ok((hook, reason.as_str().unwrap_or("?").to_owned()))
        })
        .collect()
}

fn cmd_trace_diff(
    old: &[PathBuf],
    new: Option<&Path>,
    baseline: Option<&Path>,
    hooks: &Path,
    repair: Option<&Path>,
    json: bool,
) -> Result<u8> {
    let manifest = load_manifest(hooks)?;
    let diff = match (old, new, baseline) {
        (_, _, Some(b)) => behavioral::check_baseline(&load_trace(b)?, &manifest),
        ([_, ..], Some(n), None) => {
            let held = repair.map(held_for_review).transpose()?;
            let old = old
                .iter()
                .map(|p| load_trace(p))
                .collect::<Result<Vec<_>>>()?;
            let old: Vec<&Trace> = old.iter().collect();
            behavioral::diff_traces(&old, &load_trace(n)?, &manifest, held.as_ref())
        }
        _ => anyhow::bail!("give --old and --new, or --baseline"),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        print_trace_diff(&diff);
    }
    Ok(if diff.passed() {
        EXIT_OK
    } else {
        EXIT_NEEDS_REVIEW
    })
}

fn print_trace_diff(diff: &TraceDiff) {
    for h in &diff.hooks {
        let verdict = if h.outcome.passed() { "ok  " } else { "FAIL" };
        let what = match &h.outcome {
            HookOutcome::Recorded { calls } => format!("recorded {calls} calls"),
            HookOutcome::Same { calls } => format!("same {calls} calls"),
            HookOutcome::Differs {
                call,
                expected,
                got,
            } => format!(
                "call {call} differs: expected {}, got {}",
                expected.as_deref().unwrap_or("no call"),
                got.as_deref().unwrap_or("no call")
            ),
            HookOutcome::NotFired { expected } => {
                format!("attached but never fired (old run: {expected} calls)")
            }
            HookOutcome::AttachFailed { status } => format!("attach failed: {status}"),
            HookOutcome::HeldForReview { reason } => {
                format!("not applied: needs review ({reason})")
            }
            HookOutcome::NotApplied { reason } => format!("not applied ({reason})"),
            HookOutcome::SkippedUnreported { reason } => {
                format!("not applied ({reason}) and not reported for review")
            }
            HookOutcome::AppliedDespiteReview { reason } => {
                format!("applied although repair sent it to review ({reason})")
            }
            HookOutcome::NoBaseline { calls } => {
                format!("no baseline to compare ({calls} calls, not checked)")
            }
            HookOutcome::Missing => "not in the trace".to_owned(),
        };
        println!("{verdict} {:<18} {what}", h.hook);
    }
    if !diff.completed {
        println!("FAIL run did not exit normally (crash?): the trace has no end event");
    }
    let passed = diff.hooks.iter().filter(|h| h.outcome.passed()).count();
    println!(
        "\n{passed}/{} hooks ok{}",
        diff.hooks.len(),
        if diff.passed() { "" } else { "; FAILED" }
    );
}

fn cmd_review_list(store: &Path, all: bool) -> Result<u8> {
    let store = JsonFileStore::open(store)?;
    let items: Vec<_> = store
        .review_items()
        .into_iter()
        .filter(|i| all || i.status == ReviewStatus::Open)
        .collect();
    let open = items
        .iter()
        .filter(|i| i.status == ReviewStatus::Open)
        .count();
    if items.is_empty() {
        println!("no open review items ({})", store.path().display());
        return Ok(EXIT_OK);
    }
    for item in &items {
        let reason = serde_json::to_value(item.reason)?;
        let status = serde_json::to_value(item.status)?;
        println!(
            "{} [{}]\n  reason: {}\n  old:    {}\n  detail: {}",
            item.id,
            status.as_str().unwrap_or("?"),
            reason.as_str().unwrap_or("?"),
            item.old
                .map(|r| r.to_string())
                .unwrap_or_else(|| "-".into()),
            item.detail,
        );
        if item.candidates.is_empty() {
            println!("  candidates: none");
        }
        for c in &item.candidates {
            println!(
                "  candidate {:<10} {:<14} via {} (score {:.2})",
                c.candidate.new.to_string(),
                verdict_str(c.verdict),
                source_str(&c.candidate.source),
                c.candidate.score
            );
        }
        for d in store.decisions().iter().filter(|d| d.review_id == item.id) {
            let what = match &d.action {
                DecisionAction::Accept { new } => format!("accepted {new}"),
                DecisionAction::Reject { rejected } if rejected.is_empty() => {
                    "rejected (no candidates)".to_owned()
                }
                DecisionAction::Reject { rejected } => format!(
                    "rejected {}",
                    rejected
                        .iter()
                        .map(|r| r.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            };
            println!("  decision: {what} by {}", d.reviewer);
        }
        println!();
    }
    Ok(if open > 0 { EXIT_NEEDS_REVIEW } else { EXIT_OK })
}

fn cmd_review_decide(
    store: &Path,
    id: &str,
    reviewer: &str,
    choice: Choice,
    note: Option<String>,
) -> Result<u8> {
    let mut store = JsonFileStore::open(store)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let d = store.decide(id, reviewer, choice, note, now)?;
    match &d.action {
        DecisionAction::Accept { new } => println!(
            "{id}: accepted {} -> {new}; the next `pbeta repair --store {}` uses it",
            d.old,
            store.path().display()
        ),
        DecisionAction::Reject { rejected } => println!(
            "{id}: rejected {} candidate(s) for {}; they won't be proposed again",
            rejected.len(),
            d.old
        ),
    }
    Ok(EXIT_OK)
}

fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Accepted => "accepted",
        Verdict::NeedsReview => "needs review",
        Verdict::Rejected => "rejected",
    }
}

fn source_str(s: &CandidateSource) -> String {
    match s {
        CandidateSource::Deterministic { matcher } => matcher.clone(),
        CandidateSource::Ai { model } => format!("ai:{model}"),
        CandidateSource::Human { reviewer } => format!("human:{reviewer}"),
    }
}
