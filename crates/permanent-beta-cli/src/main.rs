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
    AllOf, BehavioralRunner, TraceDiffRunner,
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

/// The AI proposer's model and its safety switches (design §8), shared by `propose` and `repair --propose`.
#[derive(clap::Args)]
struct AiArgs {
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
}

impl AiArgs {
    /// The logged model backend: live only with --allow-remote, recorded answers only with --replay.
    fn backend(&self) -> Result<permanent_beta_ai::backend::Cassette> {
        anyhow::ensure!(
            self.allow_remote || self.replay,
            "Claude is a remote model: function features, strings included, would leave this machine. Pass \
             --allow-remote to ask it (every exchange is logged to {}), or --replay to use recorded answers",
            self.log.display()
        );
        let live: Option<Box<dyn permanent_beta_ai::backend::Model>> = (!self.replay).then(|| {
            Box::new(permanent_beta_ai::backend::ClaudeCode {
                program: self.claude.clone(),
                model: self.model.clone(),
                effort: self.effort.clone(),
            }) as Box<dyn permanent_beta_ai::backend::Model>
        });
        permanent_beta_ai::backend::Cassette::open(
            &self.log,
            &format!("claude-code:{}", self.model),
            live,
        )
        .map_err(anyhow::Error::msg)
    }
}

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
        /// Where to write the analysis: minified JSON, gzip-compressed if the path ends in `.gz`. Every command
        /// that reads an analysis takes either.
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
        /// With --pdb, also record this struct's layout (repeatable), one no signature uses: what code casts an
        /// opaque pointer to (zlib's `inflate_state`). For `harness-spec --pointer-alias` and replay, which needs
        /// it in both builds' analyses.
        #[arg(long = "type", requires = "pdb")]
        types: Vec<String>,
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
        /// Behavioral evidence (design §7.3): a recording of an old build's calls (the recording hook DLL's
        /// PBETA_RECORD directory). Each candidate's recorded cases are replayed on --new-binary by emulation;
        /// with --old-trace too, a failure of either fails. Repeatable; needs --new-binary.
        #[arg(long, requires = "new_binary")]
        cases: Vec<PathBuf>,
        /// Ask the AI proposer (design §8) about hooks matching left with no candidate at all. Each proposal is
        /// verified with the hook's criticality and attached to the hook's review item; it never becomes the
        /// hook's target or a mapping, and the hook stays in review. Needs --allow-remote or --replay.
        #[arg(long)]
        propose: bool,
        #[command(flatten)]
        ai: AiArgs,
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
        #[command(flatten)]
        ai: AiArgs,
        #[arg(long)]
        json: bool,
    },
    /// Write the record spec for the recording hook DLL (design §7.3): per hook, its argument slots, how each
    /// value travels, and what each pointer points to (from the prototype and the build's PDB struct layouts).
    HarnessSpec {
        /// Hook manifest bound to the build to record.
        #[arg(long)]
        hooks: PathBuf,
        /// Analysis of that build, from `pbeta analyze --pdb` (struct layouts; without them struct pointers
        /// capture nothing).
        #[arg(long)]
        analysis: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Distinct cases recorded per hook at most.
        #[arg(long, default_value_t = permanent_beta_engine::permanent_beta_repair::harness::DEFAULT_MAX_CASES)]
        max_cases: u32,
        /// Never record this (repeatable): `hook.param` (a parameter by name or 0-based position) or
        /// `hook.global`. Nor any import call's memory that overlaps it.
        #[arg(long)]
        redact: Vec<String>,
        /// Record import calls without the memory behind their arguments (nothing derived from the hooks' data
        /// reaches the recording through an import; replay can't stand in for imports that read memory).
        #[arg(long)]
        no_import_memory: bool,
        /// Pointers to follow from the arguments' memory (design §7.3): heap blocks and buffers a struct points
        /// to. 0 captures the arguments' memory only.
        #[arg(long, default_value_t = permanent_beta_engine::permanent_beta_repair::harness::DEFAULT_POINTER_DEPTH)]
        pointer_depth: u32,
        /// `layout.field=Target` (repeatable): the pointer field may also point to a `Target` (a layout in the
        /// analysis: `pbeta analyze --type`), as when code casts an opaque pointer (zlib's
        /// `z_stream_s.state=inflate_state`). The recorder takes a heap block as `Target` only when the block is
        /// exactly that size.
        #[arg(long)]
        pointer_alias: Vec<String>,
    },
    /// Replay the cases recorded at an old RVA on a function of a new binary, by emulation (design §7.3). Exit
    /// code 0 if every replayable case matches (and one could be replayed), 1 if one differs or none could.
    Replay {
        /// Recording directory (the recording hook DLL's PBETA_RECORD). Repeatable.
        #[arg(long, required = true)]
        cases: Vec<PathBuf>,
        /// The new build's binary.
        #[arg(long)]
        binary: PathBuf,
        /// The recorded function's RVA in its build.
        #[arg(long)]
        old_rva: Rva,
        /// The function to replay the cases on, in the new binary.
        #[arg(long)]
        new_rva: Rva,
        /// Analysis of the new binary with `--pdb`: struct layouts, for translating recorded structs. Without
        /// it, cases with struct memory are inconclusive.
        #[arg(long)]
        new_analysis: Option<PathBuf>,
        /// Analysis of the recorded build with `--pdb`: addresses into its image held in recorded memory are mapped
        /// to the new image (data symbols by name, functions through the accepted matches).
        #[arg(long)]
        old_analysis: Option<PathBuf>,
        /// Also replay the cases on every other function of --new-analysis, as a control for replay itself: they
        /// should pass on none of them but those with identical code. Exit code 1 if one does.
        #[arg(long, requires = "new_analysis")]
        others: bool,
        #[arg(long)]
        json: bool,
    },
    /// Bind a hook manifest's hooks to a binary: set each placeholder `target.build` (anything but a SHA-256, e.g.
    /// `v1`), or each equal to --from, to the binary's build id. Comments and layout are kept. A hook already bound
    /// to another build is left alone: moving it is `pbeta repair`'s job. Exit code 1 if no hook was bound.
    Bind {
        #[arg(long)]
        hooks: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        /// Only hooks bound to this build (a placeholder or an id).
        #[arg(long)]
        from: Option<String>,
        /// Where to write the result (default: the manifest itself).
        #[arg(long)]
        out: Option<PathBuf>,
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
        #[arg(long, conflicts_with = "function")]
        candidate: Option<Rva>,
        /// Accept a new-build function that isn't among the candidates. It's verified first with the engine's
        /// checks and policy, from the two builds' analyses, like any candidate.
        #[arg(long, requires_all = ["old_analysis", "new_analysis"])]
        function: Option<Rva>,
        /// The item's old build's analysis (with --function).
        #[arg(long)]
        old_analysis: Option<PathBuf>,
        /// The item's new build's analysis (with --function).
        #[arg(long)]
        new_analysis: Option<PathBuf>,
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
    /// Withdraw the mapping a reviewer accepted for an item: it's revoked, repair stops using it, and the item
    /// reopens. Doesn't reject the function: reject the item after if it isn't the counterpart.
    Revoke {
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
            types,
            functions_from,
        } => cmd_analyze(
            &binary,
            &out,
            pdb.as_deref(),
            pdb_functions.as_deref(),
            &types,
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
            cases,
            propose,
            ai,
            json,
        } => {
            let backend = propose.then(|| ai.backend()).transpose()?;
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
                cases: &cases,
                proposer: backend
                    .as_ref()
                    .map(|b| (b as &dyn permanent_beta_ai::backend::Model, ai.shortlist)),
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
            ai,
            json,
        } => {
            let backend = ai.backend()?;
            cmd_propose(ProposeArgs {
                old: &old,
                new: &new,
                store: store.as_deref(),
                only: &rva,
                limit,
                shortlist: ai.shortlist,
                model: &backend,
                json,
            })
        }
        Command::Header { hooks, out } => cmd_header(&hooks, &out),
        Command::Replay {
            cases,
            binary,
            old_rva,
            new_rva,
            new_analysis,
            old_analysis,
            others,
            json,
        } => cmd_replay(ReplayArgs {
            cases: &cases,
            binary: &binary,
            old_rva,
            new_rva,
            new_analysis: new_analysis.as_deref(),
            old_analysis: old_analysis.as_deref(),
            others,
            json,
        }),
        Command::Bind {
            hooks,
            binary,
            from,
            out,
        } => cmd_bind(&hooks, &binary, from.as_deref(), out.as_deref()),
        Command::HarnessSpec {
            hooks,
            analysis,
            out,
            max_cases,
            redact,
            no_import_memory,
            pointer_depth,
            pointer_alias,
        } => cmd_harness_spec(
            &hooks,
            &analysis,
            &out,
            max_cases,
            &SpecEdits {
                redact: &redact,
                pointer_alias: &pointer_alias,
            },
            !no_import_memory,
            pointer_depth,
        ),
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
                function,
                old_analysis,
                new_analysis,
                reviewer,
                note,
                force,
                store,
            } => {
                let choice = match (function, old_analysis, new_analysis) {
                    (Some(f), Some(o), Some(n)) => {
                        verified_choice(&store, &id, f, &o, &n, &reviewer, note.as_deref(), force)?
                    }
                    _ => Choice::Accept { candidate, force },
                };
                cmd_review_decide(&store, &id, &reviewer, choice, note)
            }
            ReviewCommand::Reject {
                id,
                reviewer,
                note,
                store,
            } => cmd_review_decide(&store, &id, &reviewer, Choice::Reject, note),
            ReviewCommand::Revoke {
                id,
                reviewer,
                note,
                store,
            } => cmd_review_decide(&store, &id, &reviewer, Choice::Revoke, note),
        },
    }
}

/// Recorded cases replayed on `binary`, which must be the build `new` analyzes; struct layouts from `new`.
fn recorded_runner(
    dirs: &[PathBuf],
    binary: &Path,
    new: &permanent_beta_model::AnalysisExport,
) -> Result<permanent_beta_engine::recorded::RecordedCasesRunner> {
    use permanent_beta_engine::permanent_beta_replay::{EMULATOR, Image, Recording};
    let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let image = Image::parse(&bytes)
        .map_err(|e| anyhow::anyhow!("{}: not a PE x64 image: {e}", binary.display()))?;
    anyhow::ensure!(
        image.build == new.build.id,
        "{} is build {}, but the new analysis is of {}",
        binary.display(),
        image.build,
        new.build.id
    );
    let recordings = dirs
        .iter()
        .map(|d| Recording::load(d).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if !EMULATOR {
        eprintln!(
            "note: pbeta was built without the emulator (feature `emulator`): every recorded case is inconclusive"
        );
    }
    Ok(permanent_beta_engine::recorded::RecordedCasesRunner::new(
        recordings,
        image,
        new.types.clone(),
        new.globals.clone(),
    ))
}

/// The accepted matches of `old` → `new` (old entry, new entry): replay maps function pointers in recorded
/// memory through them (design §7.3).
fn accepted_pairs(
    old: &permanent_beta_model::AnalysisExport,
    new: &permanent_beta_model::AnalysisExport,
) -> Result<Vec<(Rva, Rva)>> {
    Ok(Engine::with_defaults()
        .match_builds(old, new)?
        .reports
        .into_iter()
        .filter(|r| r.verdict == permanent_beta_model::Verdict::Accepted)
        .map(|r| (r.candidate.old, r.candidate.new))
        .collect())
}

struct ReplayArgs<'a> {
    cases: &'a [PathBuf],
    binary: &'a Path,
    old_rva: Rva,
    new_rva: Rva,
    new_analysis: Option<&'a Path>,
    old_analysis: Option<&'a Path>,
    others: bool,
    json: bool,
}

fn cmd_replay(a: ReplayArgs) -> Result<u8> {
    use permanent_beta_engine::permanent_beta_replay::CaseOutcome;
    use permanent_beta_model::CheckOutcome;
    let new = match a.new_analysis {
        Some(p) => export::load(p)?,
        // Without an analysis there are no layouts; the build id comes from the binary.
        None => {
            let bytes = std::fs::read(a.binary)
                .with_context(|| format!("reading {}", a.binary.display()))?;
            serde_json::from_value(serde_json::json!({
                "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
                "build": { "id": permanent_beta_analysis::native::build_id(&bytes).0, "file_name": "",
                           "version": null, "machine": "x64", "pdb": null },
                "producer": { "tool": "pbeta replay", "version": "0" },
                "functions": [],
            }))?
        }
    };
    let mut runner = recorded_runner(a.cases, a.binary, &new)?;
    if let Some(p) = a.old_analysis {
        anyhow::ensure!(
            a.new_analysis.is_some(),
            "--old-analysis needs --new-analysis (addresses are mapped between the two)"
        );
        let old = export::load(p)?;
        runner = runner.with_addresses(&old, &new, &accepted_pairs(&old, &new)?);
    }
    let j = runner.judge(None, a.old_rva, a.new_rva);
    let others = a
        .others
        .then(|| runner.judge_others(None, a.old_rva, a.new_rva, &new));
    if a.json {
        let mut v = serde_json::to_value(&j)?;
        if let Some(o) = &others {
            v["others"] = serde_json::to_value(o)?;
        }
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        for c in &j.cases {
            let (what, text) = match &c.outcome {
                CaseOutcome::Pass { detail } => ("pass", detail),
                CaseOutcome::Fail { detail } => ("FAIL", detail),
                CaseOutcome::Inconclusive { reason } => ("inconclusive", reason),
            };
            println!("{:<22} {what:<12} {text}", c.test_id);
        }
        let outcome = match j.outcome {
            CheckOutcome::Pass => "pass",
            CheckOutcome::Fail => "FAIL",
            CheckOutcome::Inconclusive => "inconclusive",
        };
        println!("\n{outcome}: {}", j.detail);
        if let Some(o) = &others {
            let list = |v: &[Rva]| v.iter().map(Rva::to_string).collect::<Vec<_>>().join(", ");
            println!(
                "other functions: {} pass ({}), {} with identical code pass ({}), {} calling it pass ({}), {} it \
                 calls pass ({}), {} fail, {} inconclusive",
                o.passed.len(),
                list(&o.passed),
                o.same_code.len(),
                list(&o.same_code),
                o.calls_target.len(),
                list(&o.calls_target),
                o.called_by_target.len(),
                list(&o.called_by_target),
                o.failed,
                o.inconclusive
            );
        }
    }
    let other_passes = others.as_ref().is_some_and(|o| !o.passed.is_empty());
    Ok(match j.outcome {
        CheckOutcome::Pass if !other_passes => EXIT_OK,
        _ => EXIT_NEEDS_REVIEW,
    })
}

fn cmd_bind(hooks: &Path, binary: &Path, from: Option<&str>, out: Option<&Path>) -> Result<u8> {
    let bytes = std::fs::read(binary).with_context(|| format!("reading {}", binary.display()))?;
    let id = permanent_beta_analysis::native::build_id(&bytes).0;
    let text =
        std::fs::read_to_string(hooks).with_context(|| format!("reading {}", hooks.display()))?;
    let (bound, names) = bind_manifest(&text, &id, from)?;
    // Still a manifest.
    toml::from_str::<HookManifest>(&bound).context("the bound manifest doesn't parse")?;
    let out = out.unwrap_or(hooks);
    std::fs::write(out, bound).with_context(|| format!("writing {}", out.display()))?;
    println!(
        "bound {} hook(s) to {id}: {}",
        names.len(),
        if names.is_empty() {
            "none".into()
        } else {
            names.join(", ")
        }
    );
    Ok(if names.is_empty() {
        EXIT_NEEDS_REVIEW
    } else {
        EXIT_OK
    })
}

/// Whether a build reference is a build id (a SHA-256, 64 hex digits) rather than a placeholder.
fn is_build_id(b: &str) -> bool {
    b.len() == 64 && b.bytes().all(|c| c.is_ascii_hexdigit())
}

/// `text` (a hook manifest) with every hook bound to `from`, or to a placeholder when `from` is `None`, bound to
/// `id` instead; and the names of those hooks.
fn bind_manifest(text: &str, id: &str, from: Option<&str>) -> Result<(String, Vec<String>)> {
    let mut doc: toml_edit::DocumentMut = text.parse().context("parsing the hook manifest")?;
    let mut names = Vec::new();
    if let Some(hooks) = doc.get_mut("hook").and_then(|h| h.as_array_of_tables_mut()) {
        for h in hooks.iter_mut() {
            let name = h
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("?")
                .to_owned();
            let Some(target) = h.get_mut("target").and_then(|t| t.as_table_like_mut()) else {
                continue;
            };
            let build = target.get("build").and_then(|b| b.as_str()).unwrap_or("");
            let rebind = match from {
                Some(f) => build == f,
                None => !is_build_id(build),
            };
            if rebind {
                // Keep the value's comment and spacing.
                match target.get_mut("build").and_then(|b| b.as_value_mut()) {
                    Some(v) => {
                        let decor = v.decor().clone();
                        *v = toml_edit::Value::from(id);
                        *v.decor_mut() = decor;
                    }
                    None => {
                        target.insert("build", toml_edit::value(id));
                    }
                }
                names.push(name);
            }
        }
    }
    Ok((doc.to_string(), names))
}

/// Hand-given changes to a generated record spec: what never to record, and pointer fields' other types.
struct SpecEdits<'a> {
    redact: &'a [String],
    pointer_alias: &'a [String],
}

fn cmd_harness_spec(
    hooks: &Path,
    analysis: &Path,
    out: &Path,
    max_cases: u32,
    edits: &SpecEdits,
    import_memory: bool,
    pointer_depth: u32,
) -> Result<u8> {
    use permanent_beta_engine::permanent_beta_repair::harness;
    use permanent_beta_model::CaptureKind;
    let manifest = load_manifest(hooks)?;
    let build = export::load(analysis)?;
    let mut spec = harness::spec(&manifest, &build, max_cases);
    spec.import_memory = import_memory;
    spec.pointer_depth = pointer_depth;
    for r in edits.redact {
        harness::redact(&mut spec, r).map_err(anyhow::Error::msg)?;
    }
    for a in edits.pointer_alias {
        harness::pointer_alias(&mut spec, &build, a).map_err(anyhow::Error::msg)?;
    }
    let text = format!(
        "# Record spec for the recording hook DLL (pbeta harness-spec; design §7.3). Edit `capture` to change what\n\
         # is recorded, `redact` to never record an argument or global. Recordings can contain customer data: keep\n\
         # them local.\n{}",
        toml::to_string_pretty(&spec)?
    );
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    for h in &spec.hooks {
        let captured: Vec<String> = h
            .args
            .iter()
            .filter(|a| a.capture != CaptureKind::None)
            .map(|a| {
                let what = match (a.capture, a.layout.as_deref(), a.size) {
                    (CaptureKind::Fixed, Some(l), Some(n)) => format!("{l} ({n} bytes)"),
                    (CaptureKind::Fixed, None, Some(n)) => format!("{n} bytes"),
                    (CaptureKind::Array, _, Some(n)) => {
                        format!("{n}-byte elements (the heap block holding them)")
                    }
                    (CaptureKind::Cstring, ..) => "string".into(),
                    (CaptureKind::Sized, ..) => {
                        format!(
                            "bytes sized by {}",
                            a.len_slot.map_or("?".into(), |s| s.to_string())
                        )
                    }
                    _ => "?".into(),
                };
                format!("{} -> {what}", a.slot)
            })
            .collect();
        println!(
            "{:<18} {} args, returns {}; memory: {}",
            h.name,
            h.args.len(),
            h.ret,
            if captured.is_empty() {
                "none".to_owned()
            } else {
                captured.join(", ")
            }
        );
    }
    for s in &spec.skipped {
        println!("{:<18} skipped: {}", s.name, s.reason);
    }
    println!("spec written to {}", out.display());
    Ok(EXIT_OK)
}

fn cmd_match(old: &Path, new: &Path, json: bool) -> Result<u8> {
    let (old, new) = (export::load(old)?, export::load(new)?);
    let report = Engine::with_defaults().match_builds(&old, &new)?;

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
    /// `--cases`: recording directories.
    cases: &'a [PathBuf],
    /// `--propose`: the AI model and its shortlist length.
    proposer: Option<(&'a dyn permanent_beta_ai::backend::Model, usize)>,
    json: bool,
}

/// `repair --propose`: ask the AI proposer about every hook matching left with no candidate, from the hook's own
/// source build, and attach each verified proposal to that hook's review item. A pair a reviewer already
/// rejected is not attached again. Returns one line per hook asked.
#[allow(clippy::too_many_arguments)]
fn propose_for_unmatched(
    engine: &Engine,
    report: &mut permanent_beta_engine::RepairReport,
    manifest: &HookManifest,
    old: &permanent_beta_model::AnalysisExport,
    earlier: &[permanent_beta_model::AnalysisExport],
    new: &permanent_beta_model::AnalysisExport,
    priors: &BTreeMap<BuildId, PriorDecisions>,
    model: &dyn permanent_beta_ai::backend::Model,
    shortlist: usize,
) -> Result<Vec<String>> {
    use permanent_beta_ai::{Outcome, Proposer, shortlist::Matched};
    use permanent_beta_model::ReviewReason;
    let asks: Vec<(String, Rva, BuildId)> = report
        .repairs
        .iter()
        .filter(|r| {
            matches!(
                r.action,
                RepairAction::NeedsReview {
                    reason: ReviewReason::Unmatched,
                    ..
                }
            )
        })
        .filter_map(|r| {
            let from = r.from_build.clone().unwrap_or_else(|| old.build.id.clone());
            Some((r.hook.clone(), r.old?, from))
        })
        .collect();
    let mut proposer = Proposer::new(model);
    proposer.shortlist_len = shortlist;
    let mut pairs_by_build: BTreeMap<BuildId, Vec<permanent_beta_model::Candidate>> =
        BTreeMap::new();
    let mut notes = Vec::new();
    for (hook, rva, from) in asks {
        let Some(src) = std::iter::once(old)
            .chain(earlier)
            .find(|e| e.build.id == from)
        else {
            continue;
        };
        if !pairs_by_build.contains_key(&from) {
            let matched = engine.match_builds(src, new)?;
            pairs_by_build.insert(
                from.clone(),
                matched.reports.into_iter().map(|r| r.candidate).collect(),
            );
        }
        let pairs = &pairs_by_build[&from];
        let criticality = manifest
            .hooks
            .iter()
            .find(|h| h.name == hook)
            .map_or(Criticality::Normal, |h| h.criticality);
        let asked = proposer.ask_with(&Matched::new(src, new, pairs), src, new, rva);
        let note = match &asked.outcome {
            Outcome::Proposed { candidate } => {
                let rejected = priors
                    .get(&from)
                    .is_some_and(|p| p.rejected.contains(&(candidate.old, candidate.new)));
                match engine.verify_candidate(src, new, candidate, criticality)? {
                    _ if rejected => {
                        format!("proposed {}, already rejected by a reviewer", candidate.new)
                    }
                    Some(v) => {
                        let verdict = verdict_str(v.verdict);
                        report.attach_proposals(&hook, vec![v]);
                        format!(
                            "proposed {} (confidence {:.2}; verification: {verdict}); attached for review",
                            candidate.new, candidate.score
                        )
                    }
                    None => format!("proposed {} (couldn't be verified)", candidate.new),
                }
            }
            Outcome::Abstained { confidence, .. } => format!(
                "none of {} candidates (confidence {confidence:.2})",
                asked.shortlist.len()
            ),
            Outcome::NoShortlist => "no unmatched function close enough to ask".into(),
            Outcome::Failed { error } => format!("FAILED: {error}"),
        };
        notes.push(format!("{hook}: {note}"));
    }
    Ok(notes)
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
    let mut runners: Vec<Box<dyn BehavioralRunner>> = Vec::new();
    if let Some((o, n)) = a.traces {
        runners.push(Box::new(TraceDiffRunner::with_baselines(o, n)));
    }
    if !a.cases.is_empty() {
        let bin = a.new_binary.context("--cases needs --new-binary")?;
        let mut runner = recorded_runner(a.cases, bin, &new)?;
        for o in std::iter::once(&old).chain(&earlier) {
            // An earlier build that can't be matched to the new one is refused by the repair if a hook needs it.
            if o.features_comparable(&new).is_ok() {
                runner = runner.with_addresses(o, &new, &accepted_pairs(o, &new)?);
            }
        }
        runners.push(Box::new(runner));
    }
    let engine = match runners.len() {
        0 => Engine::with_defaults(),
        1 => Engine::with_behavioral(runners.pop().expect("one runner")),
        _ => Engine::with_behavioral(Box::new(AllOf(runners))),
    };
    let mut report = engine.repair_across(&manifest, &old, &earlier, &new, &priors)?;
    let proposal_notes = match a.proposer {
        Some((model, shortlist)) => propose_for_unmatched(
            &engine,
            &mut report,
            &manifest,
            &old,
            &earlier,
            &new,
            &priors,
            model,
            shortlist,
        )?,
        None => Vec::new(),
    };

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
            for p in &r.struct_proposals {
                println!(
                    "{:<18}   struct {} changed ({:#x} -> {:#x} bytes): {}",
                    "",
                    p.name,
                    p.old_size,
                    p.new_size,
                    p.changes.join("; ")
                );
                for line in p.offsets.lines() {
                    println!("{:<18}     {line}", "");
                }
            }
        }
        let resolved = report.repairs.iter().filter(|r| r.is_resolved()).count();
        println!("\n{resolved}/{} hooks resolved", report.repairs.len());
        for n in &pattern_notes {
            println!("pattern: {n}");
        }
        for n in &proposal_notes {
            println!("AI proposer: {n}");
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
    let report = engine.match_builds(&old, &new)?;
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
                engine.verify_candidate(&old, &new, candidate, Criticality::Normal)?
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
    types: &[String],
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
        let symbols = symbols::read_with_types(pdb, types)?;
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
                DecisionAction::Revoke { new } => format!("revoked the mapping onto {new}"),
            };
            println!("  decision: {what} by {}", d.reviewer);
        }
        println!();
    }
    Ok(if open > 0 { EXIT_NEEDS_REVIEW } else { EXIT_OK })
}

/// `review accept --function`: the reviewer's function verified like any candidate (the engine's checks and the
/// normal policy, this pair's match as neighbour context), for the store to record with its report. Prints the
/// verdict and every check, so the reviewer sees what they accept.
#[allow(clippy::too_many_arguments)]
fn verified_choice(
    store: &Path,
    id: &str,
    function: Rva,
    old_analysis: &Path,
    new_analysis: &Path,
    reviewer: &str,
    note: Option<&str>,
    force: bool,
) -> Result<Choice> {
    use permanent_beta_model::{Candidate, Evidence, evidence_kind};
    let store = JsonFileStore::open(store)?;
    let item = store
        .review_items()
        .into_iter()
        .find(|i| i.id == id)
        .with_context(|| format!("no review item with id {id}"))?;
    let old_rva = item
        .old
        .with_context(|| format!("review item {id} has no old function"))?;
    anyhow::ensure!(
        !item.candidates.iter().any(|c| c.candidate.new == function),
        "{function} is one of the candidates of {id}; accept it with --candidate"
    );
    let (old, new) = (export::load(old_analysis)?, export::load(new_analysis)?);
    anyhow::ensure!(
        old.build.id == item.from_build && new.build.id == item.to_build,
        "{id} is for {} -> {}, but the analyses are of {} -> {}",
        item.from_build,
        item.to_build,
        old.build.id,
        new.build.id
    );
    let candidate = Candidate {
        old: old_rva,
        new: function,
        source: CandidateSource::Human {
            reviewer: reviewer.to_owned(),
        },
        score: 0.0,
        evidence: vec![Evidence {
            kind: evidence_kind::REVIEWER.to_owned(),
            detail: note.unwrap_or("named by the reviewer").to_owned(),
        }],
    };
    let report = Engine::with_defaults()
        .verify_candidate(&old, &new, &candidate, Criticality::Normal)?
        .with_context(|| format!("{function} isn't a function in {}", new_analysis.display()))?;
    println!(
        "{old_rva} -> {function}: verification {}",
        verdict_str(report.verdict)
    );
    for c in &report.checks {
        println!("  {:<16} {:?}: {}", c.check, c.outcome, c.detail);
    }
    Ok(Choice::AcceptVerified {
        report: Box::new(report),
        force,
    })
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
        DecisionAction::Revoke { new } => println!(
            "{id}: revoked {} -> {new}; the item is open again (reject it if {new} isn't the counterpart)",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_sets_placeholder_builds_and_keeps_comments() {
        let other = "a".repeat(64);
        let text = format!(
            r#"# My hooks.
[[hook]]
name = "f"

[hook.target]
build = "v1" # the shipped build
rva = "0x1000"

[[hook]]
name = "g"
target = {{ build = "v1", symbol = "g" }}

[[hook]]
name = "h"

[hook.target]
build = "{other}"
rva = "0x2000"
"#
        );
        let id = "b".repeat(64);
        let (out, names) = bind_manifest(&text, &id, None).unwrap();
        assert_eq!(names, ["f", "g"]);
        assert!(
            out.contains("# My hooks.") && out.contains("# the shipped build"),
            "{out}"
        );
        let m: HookManifest = toml::from_str(&out).unwrap();
        let builds: Vec<&str> = m.hooks.iter().map(|h| h.target.build.0.as_str()).collect();
        // Negative: the hook already bound to another build stays there.
        assert_eq!(builds, [id.as_str(), id.as_str(), other.as_str()]);
        // With --from, exactly those hooks, placeholder or not.
        let (_, names) = bind_manifest(&text, &id, Some(&other)).unwrap();
        assert_eq!(names, ["h"]);
        // Negative: --from naming no hook's build binds nothing.
        let (_, names) = bind_manifest(&text, &id, Some("v2")).unwrap();
        assert!(names.is_empty());
    }
    use permanent_beta_model::{AnalysisExport, ReviewReason};

    /// Always picks the first shortlisted candidate.
    struct PickFirst;
    impl permanent_beta_ai::backend::Model for PickFirst {
        fn name(&self) -> String {
            "stub".into()
        }
        fn complete(&self, _: &permanent_beta_ai::prompt::Prompt) -> Result<String, String> {
            Ok(r#"{"choice":"c1","confidence":0.8,"rationale":"same string"}"#.into())
        }
    }

    fn export(id: &str, functions: serde_json::Value) -> AnalysisExport {
        serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": id, "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": functions,
        }))
        .unwrap()
    }

    /// The hook target 0x10 shares a string with 0x110 but nothing the passes match on: unmatched.
    fn unmatched() -> (AnalysisExport, AnalysisExport, HookManifest) {
        let old = export(
            "a",
            serde_json::json!([{ "rva": "0x10", "size": 64, "name": null, "name_source": null,
                "normalized_hash": "h1", "mnemonic_hash": null, "basic_blocks": null, "edges": null,
                "strings": ["price %d", "total"], "signature": null }]),
        );
        let new = export(
            "b",
            serde_json::json!([{ "rva": "0x110", "size": 64, "name": null, "name_source": null,
                "normalized_hash": "h2", "mnemonic_hash": null, "basic_blocks": null, "edges": null,
                "strings": ["price %d"], "signature": null }]),
        );
        let manifest: HookManifest = toml::from_str(
            "[[hook]]\nname = \"price\"\n[hook.target]\nbuild = \"a\"\nrva = \"0x10\"\n",
        )
        .unwrap();
        (old, new, manifest)
    }

    #[test]
    fn repair_propose_attaches_ai_proposals_to_review_and_never_applies_them() {
        let (old, new, manifest) = unmatched();
        let engine = Engine::with_defaults();
        let none = BTreeMap::new();
        let mut report = engine
            .repair_across(&manifest, &old, &[], &new, &none)
            .unwrap();
        let notes = propose_for_unmatched(
            &engine,
            &mut report,
            &manifest,
            &old,
            &[],
            &new,
            &none,
            &PickFirst,
            5,
        )
        .unwrap();
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("attached for review"), "{notes:?}");
        assert!(!report.repairs[0].is_resolved());
        assert!(report.mappings.is_empty());
        assert_eq!(report.updated_manifest.hooks[0].target.rva, Some(Rva(0x10)));
        let item = &report.review_items[0];
        assert_eq!(item.reason, ReviewReason::Unmatched);
        assert_eq!(item.candidates.len(), 1);
        assert!(matches!(
            item.candidates[0].candidate.source,
            CandidateSource::Ai { .. }
        ));
    }

    #[test]
    fn a_proposal_a_reviewer_rejected_is_not_attached_again() {
        // Negative: the store says 0x10 -> 0x110 is not a counterpart.
        let (old, new, manifest) = unmatched();
        let engine = Engine::with_defaults();
        let priors = BTreeMap::from([(
            old.build.id.clone(),
            PriorDecisions {
                accepted: vec![],
                rejected: vec![(Rva(0x10), Rva(0x110))],
            },
        )]);
        let mut report = engine
            .repair_across(&manifest, &old, &[], &new, &priors)
            .unwrap();
        let notes = propose_for_unmatched(
            &engine,
            &mut report,
            &manifest,
            &old,
            &[],
            &new,
            &priors,
            &PickFirst,
            5,
        )
        .unwrap();
        assert!(notes[0].contains("already rejected"), "{notes:?}");
        assert!(report.review_items[0].candidates.is_empty());
    }
}
