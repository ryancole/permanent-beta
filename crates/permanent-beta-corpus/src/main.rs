//! `pbeta-corpus`: test-corpus tooling. Used by corpus/build-fixtures.ps1.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use permanent_beta_corpus::{map, truth::GroundTruth};
use std::path::{Path, PathBuf};

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
}

fn main() -> Result<()> {
    match Cli::parse().command {
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
            Ok(())
        }
    }
}

fn load(path: &Path) -> Result<map::MapFile> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    map::parse(&text).with_context(|| format!("parsing {}", path.display()))
}
