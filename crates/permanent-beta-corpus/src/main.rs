//! `pbeta-corpus`: test-corpus tooling. Used by corpus/build-fixtures.ps1.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_analysis::native::pattern::{Pattern, PatternIndex};
use permanent_beta_corpus::ai_score;
use permanent_beta_corpus::{
    expected::Expected,
    fixture, hooks, map,
    truth::{GroundTruth, Scope},
};
use permanent_beta_engine::permanent_beta_match::SimilarityParams;
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
        /// A function renamed between the builds whose old name the new build gives to another function, as
        /// `old=new`. Repeatable. Joined before anything else; an error unless `old` is in both builds once and
        /// `new` in the new build once.
        #[arg(long = "rename-reused", value_parser = parse_rename)]
        reused: Vec<(String, String)>,
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
        /// Add each function's PDB signature to both analyses, and nothing else from the PDB (no names, types or
        /// globals), to measure the parameter-count check. The PDB is found beside each executable or, for a
        /// corpus project, in its builds/ directory, and must be that build's.
        #[arg(long)]
        pdb_signatures: bool,
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
    /// Calibrate the similarity pass: score every built variant with a grid of thresholds (design §5.1 pass 6).
    /// Prints, per setting, correct and wrong matches summed over all variants, and every variant with a wrong
    /// match.
    Sweep {
        /// Built directories (like `score --built`). Repeatable.
        #[arg(long, required = true)]
        built: Vec<PathBuf>,
        /// Minimum scores to try, comma-separated.
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "0.6,0.65,0.7,0.75,0.8,0.85,0.9"
        )]
        scores: Vec<f32>,
        /// Minimum margins to try.
        #[arg(long, value_delimiter = ',', default_value = "0.02,0.05,0.1,0.15,0.2")]
        margins: Vec<f32>,
        /// Minimum sizes (bytes) to try.
        #[arg(long, value_delimiter = ',', default_value = "8,16,32")]
        sizes: Vec<u32>,
    },
    /// Score the AI proposer (design §8) on built variants: ask about unmatched in-scope old functions, verify
    /// each proposal, and judge it against the answer key. Replays answers recorded in --log; with
    /// --allow-remote, asks Claude (through the Claude Code CLI) for the rest and records them.
    ScoreAi {
        /// Built directories (like `score --built`). Repeatable.
        #[arg(long, required = true)]
        built: Vec<PathBuf>,
        /// Only variants whose path contains this.
        #[arg(long)]
        variant: Option<String>,
        /// Questions per variant, lowest addresses first.
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Which unmatched functions to ask about: all, only deleted ones, or only ones with a counterpart.
        #[arg(long, value_enum, default_value_t = ai_score::Select::All)]
        select: ai_score::Select,
        #[arg(long, default_value = "claude-opus-5-5")]
        model: String,
        #[arg(long)]
        effort: Option<String>,
        #[arg(long, env = "PBETA_CLAUDE", default_value = "claude")]
        claude: PathBuf,
        /// Recorded exchanges: replayed, and appended to when asking live.
        #[arg(long, default_value = "corpus/ai/claude-opus-5-5.jsonl")]
        log: PathBuf,
        /// Ask Claude for answers not in the log. Function features from the corpus leave this machine.
        #[arg(long)]
        allow_remote: bool,
        /// Print every asked function with its judgement.
        #[arg(long)]
        rows: bool,
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
            pdb_signatures,
        } => {
            let symbols = if pdb_signatures {
                fixture::Symbols::Signatures
            } else {
                fixture::Symbols::None
            };
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
                let v = fixture::score_variant(&dir, &flags, &expected, symbols)?;
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
        Command::ScoreAi {
            built,
            variant,
            limit,
            select,
            model,
            effort,
            claude,
            log,
            allow_remote,
            rows,
        } => {
            use permanent_beta_ai::backend::{Cassette, ClaudeCode, Model};
            let live: Option<Box<dyn Model>> = allow_remote.then(|| {
                Box::new(ClaudeCode {
                    program: claude,
                    model: model.clone(),
                    effort,
                }) as Box<dyn Model>
            });
            let backend = Cassette::open(&log, &format!("claude-code:{model}"), live)
                .map_err(anyhow::Error::msg)?;
            eprintln!(
                "{} recorded answers in {}{}",
                backend.len(),
                log.display(),
                if allow_remote {
                    "; asking Claude for the rest"
                } else {
                    "; replay only"
                }
            );
            let mut variants: Vec<PathBuf> = Vec::new();
            for b in &built {
                let mut v: Vec<PathBuf> = std::fs::read_dir(b)
                    .with_context(|| format!("reading {}", b.display()))?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.join("truth.json").exists())
                    .filter(|p| {
                        variant
                            .as_ref()
                            .is_none_or(|s| p.to_string_lossy().contains(s.as_str()))
                    })
                    .collect();
                v.sort();
                variants.extend(v);
            }
            anyhow::ensure!(!variants.is_empty(), "no built variants");
            let mut all = ai_score::AiTotals::default();
            for dir in &variants {
                let (truth, old, new) = fixture::load_variant(dir)?;
                let (t, judged) =
                    ai_score::score_variant(&truth, &old, &new, &backend, select, limit)?;
                println!(
                    "{}",
                    ai_score::render_totals(&dir.display().to_string(), &t)
                );
                if rows {
                    for r in &judged {
                        let got = match &r.asked.outcome {
                            permanent_beta_ai::Outcome::Proposed { candidate } => {
                                candidate.new.to_string()
                            }
                            permanent_beta_ai::Outcome::Failed { error } => format!("({error})"),
                            _ => "-".into(),
                        };
                        println!(
                            "    {:<14} {:<34} old {} truth {:?} got {got}",
                            r.judgement,
                            r.names.join("/"),
                            r.old,
                            r.truth.iter().map(|t| t.to_string()).collect::<Vec<_>>()
                        );
                    }
                }
                all.add(&t);
            }
            println!("{}", ai_score::render_totals("all", &all));
            Ok(ExitCode::SUCCESS)
        }
        Command::Sweep {
            built,
            scores,
            margins,
            sizes,
        } => {
            let mut grid = Vec::new();
            for &min_size in &sizes {
                for &min_score in &scores {
                    for &min_margin in &margins {
                        grid.push(SimilarityParams {
                            min_score,
                            min_margin,
                            min_size,
                        });
                    }
                }
            }
            let mut variants: Vec<PathBuf> = Vec::new();
            for b in &built {
                let mut v: Vec<PathBuf> = std::fs::read_dir(b)
                    .with_context(|| format!("reading {}", b.display()))?
                    .filter_map(|e| e.ok().map(|e| e.path()))
                    .filter(|p| p.join("truth.json").exists())
                    .collect();
                v.sort();
                variants.extend(v);
            }
            anyhow::ensure!(!variants.is_empty(), "no built variants");
            let mut sum: Vec<fixture::SweepPoint> = Vec::new();
            let mut wrong_in: Vec<Vec<String>> = vec![Vec::new(); grid.len()];
            for dir in &variants {
                eprintln!("sweeping {}", dir.display());
                let (truth, old, new) = fixture::load_variant(dir)?;
                let points = fixture::sweep_variant(&truth, &old, &new, &grid)?;
                for (i, p) in points.iter().enumerate() {
                    if p.wrong > 0 {
                        wrong_in[i].push(format!("{} ({})", dir.display(), p.wrong));
                    }
                }
                if sum.is_empty() {
                    sum = points;
                } else {
                    for (s, p) in sum.iter_mut().zip(&points) {
                        s.correct += p.correct;
                        s.accepted += p.accepted;
                        s.wrong += p.wrong;
                        s.sim_correct += p.sim_correct;
                        s.sim_wrong += p.sim_wrong;
                    }
                }
            }
            println!(
                "{} variants. Totals over all of them:\n{:>5} {:>6} {:>7} {:>8} {:>9} {:>6} {:>10} {:>9}",
                variants.len(),
                "size",
                "score",
                "margin",
                "correct",
                "accepted",
                "wrong",
                "sim-right",
                "sim-wrong"
            );
            for (p, wrong) in sum.iter().zip(&wrong_in) {
                println!(
                    "{:>5} {:>6.2} {:>7.2} {:>8} {:>9} {:>6} {:>10} {:>9}{}",
                    p.params.min_size,
                    p.params.min_score,
                    p.params.min_margin,
                    p.correct,
                    p.accepted,
                    p.wrong,
                    p.sim_correct,
                    p.sim_wrong,
                    if wrong.is_empty() {
                        String::new()
                    } else {
                        format!("  wrong in: {}", wrong.join(", "))
                    }
                );
            }
            Ok(ExitCode::SUCCESS)
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
            reused,
            out,
        } => {
            let scope = object.map(Scope::Object).unwrap_or(Scope::ProjectObjects);
            let truth = GroundTruth::from_maps_with_declarations(
                &load(&old)?,
                &load(&new)?,
                &scope,
                &renames,
                &reused,
            )
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
    Ok(permanent_beta_analysis::export::load(path)?)
}

fn load(path: &Path) -> Result<map::MapFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    map::parse(&text).with_context(|| format!("parsing {}", path.display()))
}
