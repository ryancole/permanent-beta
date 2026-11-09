//! Ghidra's x86 SLEIGH processor specification (Ghidra 12.2, Apache-2.0; `sleigh/README.md`), embedded so that
//! replay's instruction semantics are pinned with the code and need no Ghidra install. icicle compiles it from a
//! `Ghidra/Processors` directory, so the files are unpacked once to a directory under the system temp directory
//! named after their content hash, and reused from there.

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::OnceLock;

/// `Ghidra/Processors/x86/data/languages/<name>`.
const FILES: &[(&str, &[u8])] = &[
    (
        "adx.sinc",
        include_bytes!("../sleigh/x86/data/languages/adx.sinc"),
    ),
    (
        "avx.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx.sinc"),
    ),
    (
        "avx2.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx2.sinc"),
    ),
    (
        "avx2_manual.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx2_manual.sinc"),
    ),
    (
        "avx512.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx512.sinc"),
    ),
    (
        "avx512_manual.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx512_manual.sinc"),
    ),
    (
        "avx_manual.sinc",
        include_bytes!("../sleigh/x86/data/languages/avx_manual.sinc"),
    ),
    (
        "bmi1.sinc",
        include_bytes!("../sleigh/x86/data/languages/bmi1.sinc"),
    ),
    (
        "bmi2.sinc",
        include_bytes!("../sleigh/x86/data/languages/bmi2.sinc"),
    ),
    (
        "cet.sinc",
        include_bytes!("../sleigh/x86/data/languages/cet.sinc"),
    ),
    (
        "clwb.sinc",
        include_bytes!("../sleigh/x86/data/languages/clwb.sinc"),
    ),
    (
        "cmpccxadd.sinc",
        include_bytes!("../sleigh/x86/data/languages/cmpccxadd.sinc"),
    ),
    (
        "fma.sinc",
        include_bytes!("../sleigh/x86/data/languages/fma.sinc"),
    ),
    (
        "gfni.sinc",
        include_bytes!("../sleigh/x86/data/languages/gfni.sinc"),
    ),
    (
        "ia.sinc",
        include_bytes!("../sleigh/x86/data/languages/ia.sinc"),
    ),
    (
        "lockable.sinc",
        include_bytes!("../sleigh/x86/data/languages/lockable.sinc"),
    ),
    (
        "lzcnt.sinc",
        include_bytes!("../sleigh/x86/data/languages/lzcnt.sinc"),
    ),
    (
        "macros.sinc",
        include_bytes!("../sleigh/x86/data/languages/macros.sinc"),
    ),
    (
        "mpx.sinc",
        include_bytes!("../sleigh/x86/data/languages/mpx.sinc"),
    ),
    (
        "pclmulqdq.sinc",
        include_bytes!("../sleigh/x86/data/languages/pclmulqdq.sinc"),
    ),
    (
        "rao.sinc",
        include_bytes!("../sleigh/x86/data/languages/rao.sinc"),
    ),
    (
        "rdrand.sinc",
        include_bytes!("../sleigh/x86/data/languages/rdrand.sinc"),
    ),
    (
        "sgx.sinc",
        include_bytes!("../sleigh/x86/data/languages/sgx.sinc"),
    ),
    (
        "sha.sinc",
        include_bytes!("../sleigh/x86/data/languages/sha.sinc"),
    ),
    (
        "smx.sinc",
        include_bytes!("../sleigh/x86/data/languages/smx.sinc"),
    ),
    (
        "x86-16-real.pspec",
        include_bytes!("../sleigh/x86/data/languages/x86-16-real.pspec"),
    ),
    (
        "x86-16.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86-16.cspec"),
    ),
    (
        "x86-16.pspec",
        include_bytes!("../sleigh/x86/data/languages/x86-16.pspec"),
    ),
    (
        "x86-32-golang.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86-32-golang.cspec"),
    ),
    (
        "x86-32-golang.register.info",
        include_bytes!("../sleigh/x86/data/languages/x86-32-golang.register.info"),
    ),
    (
        "x86-64-compat32.pspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64-compat32.pspec"),
    ),
    (
        "x86-64-gcc.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64-gcc.cspec"),
    ),
    (
        "x86-64-golang.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64-golang.cspec"),
    ),
    (
        "x86-64-golang.register.info",
        include_bytes!("../sleigh/x86/data/languages/x86-64-golang.register.info"),
    ),
    (
        "x86-64-win.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64-win.cspec"),
    ),
    (
        "x86-64.pspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64.pspec"),
    ),
    (
        "x86-64.slaspec",
        include_bytes!("../sleigh/x86/data/languages/x86-64.slaspec"),
    ),
    (
        "x86.ldefs",
        include_bytes!("../sleigh/x86/data/languages/x86.ldefs"),
    ),
    (
        "x86.pspec",
        include_bytes!("../sleigh/x86/data/languages/x86.pspec"),
    ),
    (
        "x86.slaspec",
        include_bytes!("../sleigh/x86/data/languages/x86.slaspec"),
    ),
    (
        "x86borland.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86borland.cspec"),
    ),
    (
        "x86delphi.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86delphi.cspec"),
    ),
    (
        "x86gcc.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86gcc.cspec"),
    ),
    (
        "x86win.cspec",
        include_bytes!("../sleigh/x86/data/languages/x86win.cspec"),
    ),
];

/// The `Ghidra/Processors` directory holding the embedded x86 specification, unpacked on first use.
pub fn processors() -> Result<PathBuf, String> {
    static DIR: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    DIR.get_or_init(unpack).clone()
}

fn unpack() -> Result<PathBuf, String> {
    let mut h = Sha256::new();
    for (name, bytes) in FILES {
        h.update(name.as_bytes());
        h.update([0]);
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    }
    let digest: String = h.finalize()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let root = std::env::temp_dir().join(format!("permanent-beta-sleigh-{digest}"));
    let processors = root.join("Ghidra").join("Processors");
    let languages = processors.join("x86").join("data").join("languages");
    let complete = |dir: &std::path::Path| {
        FILES.iter().all(|(name, bytes)| {
            std::fs::metadata(dir.join(name)).is_ok_and(|m| m.len() == bytes.len() as u64)
        })
    };
    if complete(&languages) {
        return Ok(processors);
    }
    // Written beside the final place and renamed into it, so a concurrent replay never sees half the files.
    let staging = std::env::temp_dir().join(format!(
        "permanent-beta-sleigh-{digest}.{}.tmp",
        std::process::id()
    ));
    let staged = staging.join("x86").join("data").join("languages");
    let io =
        |what: &str, e: std::io::Error| format!("unpacking the SLEIGH specification ({what}): {e}");
    std::fs::create_dir_all(&staged).map_err(|e| io("create", e))?;
    for (name, bytes) in FILES {
        std::fs::write(staged.join(name), bytes).map_err(|e| io(name, e))?;
    }
    std::fs::create_dir_all(&processors).map_err(|e| io("create", e))?;
    let target = processors.join("x86");
    if std::fs::rename(staging.join("x86"), &target).is_err() && !complete(&languages) {
        return Err(format!(
            "unpacking the SLEIGH specification: couldn't move it to {}",
            target.display()
        ));
    }
    let _ = std::fs::remove_dir_all(&staging);
    Ok(processors)
}
