//! `pbeta-mcp`: the Permanent Beta MCP server over stdio (design §11.2).
//!
//! ```text
//! pbeta-mcp --analysis v1.json --analysis v2.json [--store .pbeta/store.json]
//! ```
//!
//! Logs go to stderr; stdout carries only protocol messages.

use anyhow::{Context, Result, bail};
use clap::Parser;
use permanent_beta_mcp::{Server, tools::Tools};
use permanent_beta_model::{ANALYSIS_SCHEMA_VERSION, AnalysisExport};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "pbeta-mcp",
    version,
    about = "Permanent Beta MCP server (stdio)"
)]
struct Cli {
    /// An analysis export (`pbeta analyze`). Repeatable: every build the agent may look at. Optional: the review
    /// tools need only the store (the Ghidra extension starts it that way).
    #[arg(long)]
    analysis: Vec<PathBuf>,
    /// Review store. Read for review items; proposals are added to it. Without it, the review tools and
    /// propose_mapping report an error.
    #[arg(long)]
    store: Option<PathBuf>,
}

fn load(path: &PathBuf) -> Result<AnalysisExport> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    // `pbeta analyze` gzips a `.gz` output; recognized by content, as `permanent_beta_analysis::export::load`
    // does (this crate may not depend on analysis).
    let text = if bytes.starts_with(&[0x1f, 0x8b]) {
        use std::io::Read;
        let mut text = String::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut text)
            .with_context(|| format!("decompressing {}", path.display()))?;
        text
    } else {
        String::from_utf8(bytes).with_context(|| format!("reading {}", path.display()))?
    };
    let a: AnalysisExport = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .with_context(|| format!("parsing {}", path.display()))?;
    if a.schema_version != ANALYSIS_SCHEMA_VERSION {
        bail!(
            "{}: analysis schema version {} (expected {ANALYSIS_SCHEMA_VERSION})",
            path.display(),
            a.schema_version
        );
    }
    Ok(a)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let analyses = cli.analysis.iter().map(load).collect::<Result<Vec<_>>>()?;
    eprintln!(
        "pbeta-mcp: {} builds loaded{}",
        analyses.len(),
        cli.store
            .as_ref()
            .map(|s| format!(", store {}", s.display()))
            .unwrap_or_default()
    );
    let mut server = Server::new(Tools::new(analyses, cli.store));
    let stdin = std::io::stdin();
    server.serve(stdin.lock(), std::io::stdout().lock())?;
    Ok(())
}
