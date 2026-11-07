//! `pbeta` CLI. Thin layer: argument parsing, file I/O, output formatting, exit codes.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_analysis::{Analyzer, export, native::NativePeAnalyzer};
use permanent_beta_engine::Engine;
use permanent_beta_engine::permanent_beta_repair::RepairAction;
use permanent_beta_model::{
    CandidateSource, DecisionAction, HookManifest, PriorDecisions, ReviewStatus, Rva, Verdict,
};
use permanent_beta_store::{Choice, JsonFileStore, MappingStore};
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
    /// Analyze a binary into the normalized AnalysisExport JSON (native analyzer: not implemented yet).
    Analyze {
        binary: PathBuf,
        #[arg(long)]
        out: PathBuf,
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
        /// Write the repaired manifest here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Record accepted mappings and review items in this store, and honor its review decisions.
        #[arg(long)]
        store: Option<PathBuf>,
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
        Command::Analyze { binary, out } => {
            let analysis = NativePeAnalyzer.analyze(&binary)?;
            export::save(&analysis, &out)?;
            Ok(EXIT_OK)
        }
        Command::Match { old, new, json } => cmd_match(&old, &new, json),
        Command::Repair {
            old,
            new,
            hooks,
            out,
            store,
            json,
        } => cmd_repair(&old, &new, &hooks, out.as_deref(), store.as_deref(), json),
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

fn cmd_repair(
    old: &Path,
    new: &Path,
    hooks: &Path,
    out: Option<&Path>,
    store: Option<&Path>,
    json: bool,
) -> Result<u8> {
    let (old, new) = (export::load(old)?, export::load(new)?);
    let manifest: HookManifest = toml::from_str(
        &std::fs::read_to_string(hooks).with_context(|| format!("reading {}", hooks.display()))?,
    )
    .with_context(|| format!("parsing hook manifest {}", hooks.display()))?;

    let mut opened = store.map(JsonFileStore::open).transpose()?;
    let prior = opened
        .as_ref()
        .map(|s| s.prior_decisions(&old.build.id, &new.build.id))
        .unwrap_or_else(PriorDecisions::default);
    let report = Engine::with_defaults().repair_with(&manifest, &old, &new, &prior);

    if let Some(out) = out {
        std::fs::write(out, toml::to_string_pretty(&report.updated_manifest)?)
            .with_context(|| format!("writing {}", out.display()))?;
    }
    if let Some(store) = opened.as_mut() {
        store.put_mappings(&report.mappings)?;
        store.enqueue_review(&report.review_items)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for r in &report.repairs {
            let by = r
                .reviewed_by
                .as_ref()
                .map(|who| format!(" (decided by {who})"))
                .unwrap_or_default();
            let outcome = match &r.action {
                RepairAction::Unchanged { rva } => format!("unchanged at {rva}{by}"),
                RepairAction::Relocated { old, new } => format!("relocated {old} -> {new}{by}"),
                RepairAction::NeedsReview { reason, detail } => {
                    format!(
                        "NEEDS REVIEW ({}): {detail}",
                        serde_json::to_value(reason)?.as_str().unwrap_or("?")
                    )
                }
            };
            println!("{:<18} {outcome}", r.hook);
        }
        let resolved = report.repairs.iter().filter(|r| r.is_resolved()).count();
        println!("\n{resolved}/{} hooks resolved", report.repairs.len());
        if let Some(out) = out {
            println!("repaired manifest written to {}", out.display());
        }
    }
    Ok(if report.needs_review() {
        EXIT_NEEDS_REVIEW
    } else {
        EXIT_OK
    })
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
