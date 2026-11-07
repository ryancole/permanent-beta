//! `pbeta-corpus`: test-corpus tooling. Used by corpus/build-fixtures.ps1.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_analysis::native::pattern::{Pattern, PatternIndex};
use permanent_beta_corpus::{
    expected::Expected,
    fixture, hooks, map,
    truth::{GroundTruth, Scope},
};
use permanent_beta_model::{AnalysisExport, HookManifest};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "pbeta-corpus",
    version,
    about = "Permanent Beta test-corpus tooling"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// Parsed once per run; boxing variants would only complicate the clap derive.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Build the ground-truth function mapping from two linker map files.
    Truth {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// Only functions defined in this object file are in scope, e.g. fixture.obj. Omit to include every
        /// object file linked directly (the project's own code), excluding library members.
        #[arg(long)]
        object: Option<String>,
        /// A function renamed between the builds, as `old=new`. Repeatable. Checked against the sources by
        /// hand; an error if it doesn't name exactly one otherwise-unjoined function on each side.
        #[arg(long = "rename", value_parser = parse_rename)]
        renames: Vec<(String, String)>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Analyze, match and score every built variant of a fixture. Exits 1 if any gate fails.
    Score {
        /// Built directory with one subdirectory per variant, each holding v1/<name>.exe, v2/<name>.exe and
        /// truth.json, e.g. target/fixtures/basic or target/corpus/zlib.
        #[arg(long)]
        built: PathBuf,
        /// Expected outcomes, e.g. corpus/fixtures/basic/expected.toml.
        #[arg(long)]
        expected: PathBuf,
        /// Also list the functions present in both builds that weren't matched correctly.
        #[arg(long)]
        misses: bool,
    },
    /// Write the v1 hook manifest from a template whose locators name symbols (corpus/hooks).
    HookManifest {
        #[arg(long)]
        template: PathBuf,
        /// Linker map of the build the hooks are written for.
        #[arg(long)]
        map: PathBuf,
        /// `pbeta analyze` output of that build (for its build id).
        #[arg(long)]
        analysis: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Check a repaired hook manifest against the answer key. Exits 1 on any wrong relocation, or when a step's
    /// expectations (--expected) aren't met.
    HookCheck {
        #[arg(long)]
        old_map: PathBuf,
        #[arg(long)]
        new_map: PathBuf,
        /// The manifest repair started from.
        #[arg(long)]
        old_hooks: PathBuf,
        /// The repaired manifest.
        #[arg(long)]
        new_hooks: PathBuf,
        #[arg(long)]
        old_analysis: PathBuf,
        #[arg(long)]
        new_analysis: PathBuf,
        /// An older build that hooks may be repaired from directly: its map. Pairs with --earlier-analysis, in
        /// the same order. Repeatable.
        #[arg(long)]
        earlier_map: Vec<PathBuf>,
        #[arg(long)]
        earlier_analysis: Vec<PathBuf>,
        /// The new binary: every re-bound hook's AOB pattern must match exactly once, at its RVA.
        #[arg(long)]
        new_binary: Option<PathBuf>,
        /// corpus/hooks/expected.toml; with --flags and --step, also enforce that step's baseline.
        #[arg(long, requires_all = ["flags", "step"])]
        expected: Option<PathBuf>,
        #[arg(long)]
        flags: Option<String>,
        #[arg(long)]
        step: Option<String>,
    },
    /// Swap two hooks' RVAs: a deliberately wrong relocation for negative controls.
    HookSwap {
        #[arg(long)]
        hooks: PathBuf,
        #[arg(long)]
        a: String,
        #[arg(long)]
        b: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Score {
            built,
            expected,
            misses,
        } => {
            let text = std::fs::read_to_string(&expected)
                .with_context(|| format!("reading {}", expected.display()))?;
            let expected = Expected::parse(&text)
                .with_context(|| format!("parsing {}", expected.display()))?;
            let mut variants: Vec<PathBuf> = std::fs::read_dir(&built)
                .with_context(|| format!("reading {}", built.display()))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join("truth.json").exists())
                .collect();
            variants.sort();
            anyhow::ensure!(
                !variants.is_empty(),
                "no built variants in {}",
                built.display()
            );

            let mut failed = false;
            for dir in variants {
                let flags = dir
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let v = fixture::score_variant(&dir, &flags, &expected)?;
                print!("{}", fixture::render(&v));
                if misses {
                    print!("{}", fixture::render_misses(&v));
                }
                failed |= !v.evaluation.gate_failures.is_empty();
            }
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::HookManifest {
            template,
            map,
            analysis,
            out,
        } => {
            let build = load_analysis(&analysis)?.build.id;
            let manifest =
                hooks::manifest_from_template(&load_hooks(&template)?, &load(&map)?, &build)
                    .map_err(anyhow::Error::msg)?;
            write_hooks(&manifest, &out)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::HookCheck {
            old_map,
            new_map,
            old_hooks,
            new_hooks,
            old_analysis,
            new_analysis,
            earlier_map,
            earlier_analysis,
            new_binary,
            expected,
            flags,
            step,
        } => {
            anyhow::ensure!(
                earlier_map.len() == earlier_analysis.len(),
                "give one --earlier-analysis per --earlier-map"
            );
            let mut builds = vec![load_analysis(&old_analysis)?.build.id];
            let mut maps = vec![load(&old_map)?];
            for (m, a) in earlier_map.iter().zip(&earlier_analysis) {
                builds.push(load_analysis(a)?.build.id);
                maps.push(load(m)?);
            }
            let sources: Vec<_> = builds.iter().zip(&maps).collect();
            let index = new_binary
                .map(|p| -> Result<_> {
                    let bytes =
                        std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
                    PatternIndex::new(&bytes).map_err(anyhow::Error::msg)
                })
                .transpose()?;
            let finder = |text: &str| -> Result<Vec<u64>, String> {
                let p: Pattern = text.parse()?;
                Ok(index.as_ref().map(|ix| ix.find(&p)).unwrap_or_default())
            };
            let checks = hooks::check_hooks(
                &load_hooks(&old_hooks)?,
                &load_hooks(&new_hooks)?,
                &sources,
                &load(&new_map)?,
                &load_analysis(&new_analysis)?.build.id,
                index.as_ref().map(|_| &finder as hooks::PatternFinder),
            );
            let expected = expected
                .map(|p| -> Result<hooks::HookExpected> {
                    let text = std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    hooks::HookExpected::parse(&text)
                        .with_context(|| format!("parsing {}", p.display()))
                })
                .transpose()?;
            let (flags, step) = (flags.unwrap_or_default(), step.unwrap_or_default());
            let step_expected = expected.as_ref().and_then(|e| e.step(&step, &flags));
            if expected.is_some() && step_expected.is_none() {
                anyhow::bail!(
                    "no [[step]] with name = {step:?} and flags = {flags:?} in the expected file"
                );
            }
            for c in &checks {
                let what = match &c.truth {
                    hooks::HookTruth::Correct { symbol, old, new } => {
                        let pattern = if index.is_some() {
                            let h = load_hooks(&new_hooks)?;
                            match h
                                .hooks
                                .iter()
                                .find(|x| x.name == c.hook)
                                .and_then(|x| x.target.pattern.clone())
                            {
                                Some(_) => ", pattern unique",
                                None => ", no pattern",
                            }
                        } else {
                            ""
                        };
                        format!("correct  {old} -> {new} ({symbol}{pattern})")
                    }
                    hooks::HookTruth::Wrong { detail, .. } => format!("WRONG    {detail}"),
                    hooks::HookTruth::Held => "held     (not re-bound: review)".to_owned(),
                };
                println!("answer key {:<18} {what}", c.hook);
            }
            let failures = hooks::gate(&checks, step_expected);
            for f in &failures {
                println!("answer key FAIL {f}");
            }
            Ok(if failures.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Command::HookSwap {
            hooks: path,
            a,
            b,
            out,
        } => {
            let swapped = hooks::swap(&load_hooks(&path)?, &a, &b).map_err(anyhow::Error::msg)?;
            write_hooks(&swapped, &out)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Truth {
            old,
            new,
            object,
            renames,
            out,
        } => {
            let scope = object.map(Scope::Object).unwrap_or(Scope::ProjectObjects);
            let truth =
                GroundTruth::from_maps_with_renames(&load(&old)?, &load(&new)?, &scope, &renames)
                    .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                !truth.functions.is_empty(),
                "no in-scope functions ({}) found in either map file",
                truth.object
            );
            std::fs::write(&out, serde_json::to_string_pretty(&truth)?)
                .with_context(|| format!("writing {}", out.display()))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn parse_rename(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((a, b)) if !a.is_empty() && !b.is_empty() => Ok((a.to_owned(), b.to_owned())),
        _ => Err(format!("expected old=new, got `{s}`")),
    }
}

fn load_hooks(path: &Path) -> Result<HookManifest> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn write_hooks(manifest: &HookManifest, path: &Path) -> Result<()> {
    std::fs::write(path, toml::to_string_pretty(manifest)?)
        .with_context(|| format!("writing {}", path.display()))
}

fn load_analysis(path: &Path) -> Result<AnalysisExport> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn load(path: &Path) -> Result<map::MapFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    map::parse(&text).with_context(|| format!("parsing {}", path.display()))
}
