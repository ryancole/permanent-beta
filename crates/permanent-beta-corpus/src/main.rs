//! `pbeta-corpus`: test-corpus tooling. Used by corpus/build-fixtures.ps1.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_corpus::{expected::Expected, fixture, map, truth::GroundTruth};
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
enum Command {
    /// Build the ground-truth function mapping from two linker map files.
    Truth {
        #[arg(long)]
        old: PathBuf,
        #[arg(long)]
        new: PathBuf,
        /// Only functions defined in this object file are in scope, e.g. fixture.obj.
        #[arg(long)]
        object: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Analyze, match and score every built variant of a fixture. Exits 1 if any gate fails.
    Score {
        /// Built fixture directory, e.g. target/fixtures/basic (one subdirectory per flag set).
        #[arg(long)]
        built: PathBuf,
        /// Expected outcomes, e.g. corpus/fixtures/basic/expected.toml.
        #[arg(long)]
        expected: PathBuf,
    },
}

fn main() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Score { built, expected } => {
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
                failed |= !v.evaluation.gate_failures.is_empty();
            }
            Ok(if failed {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            })
        }
        Command::Truth {
            old,
            new,
            object,
            out,
        } => {
            let truth = GroundTruth::from_maps(&load(&old)?, &load(&new)?, &object);
            anyhow::ensure!(
                !truth.functions.is_empty(),
                "no functions from {object} found in either map file"
            );
            std::fs::write(&out, serde_json::to_string_pretty(&truth)?)
                .with_context(|| format!("writing {}", out.display()))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load(path: &Path) -> Result<map::MapFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    map::parse(&text).with_context(|| format!("parsing {}", path.display()))
}
