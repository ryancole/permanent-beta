//! The hook host's configuration (`pbeta host-config`, `harness/host`): what the generic hook DLL attaches in
//! each build, from the repaired hook manifests.
//!
//! The host is one DLL for any x64 program. It hashes the executable it's loaded into and attaches only the hooks
//! listed for that build, at their RVAs, after checking each one's pattern. What it does per call is the hook's
//! `detour` in the manifest, its **action**:
//!
//! - `log` (the default): log each call's arguments and result, then return what the original returned;
//! - `skip`: log the call and don't call the original; return 0;
//! - `return <n>`: log the call and don't call the original; return `n` (integer or pointer results only);
//! - `<file.dll>!<export>`: a handler DLL's function (`harness/host/include/pbeta_handler.h`), attached in the
//!   original's place, with the original reachable through the handler's `pbeta_original_<export>`.
//!
//! The log decodes each argument from its Win64 slot by the hook's prototype (the manifest's, or the build's PDB
//! signature from `--analysis`); without one it logs the four integer argument registers.
//!
//! A hook is listed for the build its locator is bound to, so one that `repair` sent to review stays on the build
//! where it was verified and is never attached in the new one.

use crate::harness::value_type;
use crate::prototype::Prototype;
use permanent_beta_model::{
    AnalysisExport, ArgSlot, BuildId, FunctionSignature, HookManifest, Rva, SkippedHook, ValueType,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const HOST_CONFIG_VERSION: u32 = 1;

/// Most parameters a hook with a built-in action can have: four in registers and the eight stack slots the host's
/// generic thunk forwards. A handler is attached directly and has no limit.
pub const MAX_PARAMS: usize = 12;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostConfig {
    pub version: u32,
    #[serde(rename = "hook", default)]
    pub hooks: Vec<HostHook>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostHook {
    /// The build this entry is valid in. The host attaches it only in that exact executable.
    pub build: BuildId,
    pub name: String,
    pub rva: Rva,
    /// Checked against the code at `rva` before attaching, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// `log`, `skip`, `return <n>` or `<file.dll>!<export>` ([`Action`]).
    pub action: String,
    /// The C prototype the log decodes arguments by. Without it the log shows the four integer argument registers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ret: Option<ValueType>,
    #[serde(rename = "arg", default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<HostArg>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostArg {
    pub slot: ArgSlot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type")]
    pub ty: String,
    pub value: ValueType,
    /// Print what the pointer points to as text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub show: Option<Show>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Show {
    /// A NUL-terminated `char` string.
    Cstring,
    /// A NUL-terminated `wchar_t` (UTF-16) string.
    Wstring,
}

/// What the host does when a hooked function is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Log,
    Skip,
    Return(i64),
    Handler { dll: String, export: String },
}

impl Action {
    /// From a manifest's `detour` (none is `log`).
    pub fn parse(detour: Option<&str>) -> Result<Self, String> {
        let Some(text) = detour.map(str::trim) else {
            return Ok(Self::Log);
        };
        match text {
            "log" => return Ok(Self::Log),
            "skip" => return Ok(Self::Skip),
            _ => {}
        }
        if let Some(n) = text.strip_prefix("return ") {
            let n = n.trim();
            let parsed = match n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).map(|v| v as i64).ok(),
                None => n.parse::<i64>().ok(),
            };
            return parsed
                .map(Self::Return)
                .ok_or_else(|| format!("`return` needs an integer, got {n:?}"));
        }
        if let Some((dll, export)) = text.split_once('!') {
            let (dll, export) = (dll.trim(), export.trim());
            let ident = !export.is_empty()
                && !export.starts_with(|c: char| c.is_ascii_digit())
                && export
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_');
            if dll.to_ascii_lowercase().ends_with(".dll") && ident {
                return Ok(Self::Handler {
                    dll: dll.to_owned(),
                    export: export.to_owned(),
                });
            }
        }
        Err(format!(
            "unknown action {text:?}: use log, skip, return <n> or <file.dll>!<export>"
        ))
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Log => f.write_str("log"),
            Self::Skip => f.write_str("skip"),
            Self::Return(n) => write!(f, "return {n}"),
            Self::Handler { dll, export } => write!(f, "{dll}!{export}"),
        }
    }
}

/// The host configuration for every hook in `manifests` with an RVA, each listed for the build it's bound to.
/// `analyses` supply a PDB signature for hooks whose manifest has no prototype (matched by build).
///
/// A hook in several manifests for the same build (a manifest and the repaired one that left it in review) is
/// listed once; differing entries are an error, as is an unknown action, a `return` for a floating-point result,
/// or a built-in action on a function with more than [`MAX_PARAMS`] parameters.
pub fn config(
    manifests: &[HookManifest],
    analyses: &[AnalysisExport],
) -> Result<(HostConfig, Vec<SkippedHook>), String> {
    let mut hooks: Vec<HostHook> = Vec::new();
    let mut skipped = Vec::new();
    for manifest in manifests {
        for hook in &manifest.hooks {
            let action =
                Action::parse(hook.detour.as_deref()).map_err(|e| format!("{}: {e}", hook.name))?;
            let Some(rva) = hook.target.rva else {
                skipped.push(SkippedHook {
                    name: hook.name.clone(),
                    reason: "no RVA".into(),
                });
                continue;
            };
            let build = &hook.target.build;
            let signature = analyses
                .iter()
                .find(|a| &a.build.id == build)
                .and_then(|a| a.function(rva))
                .and_then(|f| f.signature.as_ref());
            let prototype = hook
                .prototype
                .clone()
                .or_else(|| signature.map(|s| render(&hook.name, s)));
            let parsed = prototype.as_deref().and_then(Prototype::parse);
            let mut entry = HostHook {
                build: build.clone(),
                name: hook.name.clone(),
                rva,
                pattern: hook.target.pattern.clone(),
                action: action.to_string(),
                prototype: None,
                ret: None,
                args: Vec::new(),
            };
            if let (Some(text), Some(p)) = (&prototype, &parsed) {
                if !matches!(action, Action::Handler { .. }) && p.params.len() > MAX_PARAMS {
                    return Err(format!(
                        "{}: {} parameters; `{action}` handles at most {MAX_PARAMS}, use a handler",
                        hook.name,
                        p.params.len()
                    ));
                }
                let ret = host_value_type(&p.return_type());
                if let (Action::Return(_), ValueType::Float(_)) = (&action, ret) {
                    return Err(format!(
                        "{}: `{action}` can't return a floating-point result",
                        hook.name
                    ));
                }
                entry.prototype = Some(text.clone());
                entry.ret = Some(ret);
                entry.args = p
                    .params
                    .iter()
                    .enumerate()
                    .map(|(i, param)| {
                        let value = host_value_type(&param.ty);
                        HostArg {
                            slot: ArgSlot::for_param(i as u32, value.in_vector_register()),
                            name: param.name.clone(),
                            ty: param.ty.clone(),
                            value,
                            show: show(&param.ty),
                        }
                    })
                    .collect();
            }
            match hooks
                .iter()
                .find(|h| h.build == entry.build && h.name == entry.name)
            {
                Some(h) if *h == entry => {}
                Some(_) => {
                    return Err(format!(
                        "{}: listed twice for build {} with different entries",
                        entry.name, entry.build
                    ));
                }
                None => hooks.push(entry),
            }
        }
    }
    Ok((
        HostConfig {
            version: HOST_CONFIG_VERSION,
            hooks,
        },
        skipped,
    ))
}

/// A C prototype from a PDB signature (names from the PDB when it has them).
fn render(name: &str, s: &FunctionSignature) -> String {
    let params: Vec<String> = s
        .params
        .iter()
        .map(|p| match &p.name {
            Some(n) => format!("{} {n}", p.ty),
            None => p.ty.clone(),
        })
        .collect();
    format!(
        "{} {name}({})",
        s.return_type.as_deref().unwrap_or("void"),
        params.join(", ")
    )
}

/// Windows typedefs that the record spec's [`value_type`] doesn't know, for the log only.
fn host_value_type(ty: &str) -> ValueType {
    let words: Vec<&str> = ty
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile"))
        .collect();
    match words.as_slice() {
        [w] if POINTER_TYPEDEFS.contains(w) => ValueType::Pointer,
        [w] if matches!(*w, "WPARAM" | "LPARAM" | "LRESULT") => ValueType::Int(8),
        [w] if matches!(*w, "HRESULT" | "NTSTATUS") => ValueType::Int(4),
        _ => value_type(ty),
    }
}

const POINTER_TYPEDEFS: &[&str] = &[
    "HWND",
    "HANDLE",
    "HMODULE",
    "HINSTANCE",
    "HDC",
    "HKEY",
    "HMENU",
    "HICON",
    "HBRUSH",
    "HFONT",
    "HBITMAP",
    "HGLOBAL",
    "HLOCAL",
    "HMONITOR",
    "LPVOID",
    "PVOID",
    "LPCVOID",
    "LPSTR",
    "LPCSTR",
    "PSTR",
    "PCSTR",
    "LPWSTR",
    "LPCWSTR",
    "PWSTR",
    "PCWSTR",
];

/// Whether a parameter of type `ty` is text worth printing.
fn show(ty: &str) -> Option<Show> {
    let compact: String = ty
        .split_whitespace()
        .filter(|w| !matches!(*w, "const" | "volatile" | "signed"))
        .collect::<Vec<_>>()
        .join(" ");
    match compact.as_str() {
        "char*" | "char *" | "LPSTR" | "LPCSTR" | "PSTR" | "PCSTR" => Some(Show::Cstring),
        "wchar_t*" | "wchar_t *" | "WCHAR*" | "WCHAR *" | "LPWSTR" | "LPCWSTR" | "PWSTR"
        | "PCWSTR" => Some(Show::Wstring),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        ANALYSIS_SCHEMA_VERSION, BuildInfo, Criticality, FunctionFeatures, HookSpec, Machine,
        Param, Producer, TargetLocator,
    };

    fn hook(
        name: &str,
        build: &str,
        rva: Option<u64>,
        detour: Option<&str>,
        proto: Option<&str>,
    ) -> HookSpec {
        HookSpec {
            name: name.into(),
            detour: detour.map(str::to_owned),
            criticality: Criticality::Normal,
            prototype: proto.map(str::to_owned),
            trial: false,
            target: TargetLocator {
                build: BuildId(build.into()),
                rva: rva.map(Rva),
                symbol: None,
                pattern: None,
            },
        }
    }

    fn manifest(hooks: Vec<HookSpec>) -> HookManifest {
        HookManifest { hooks }
    }

    #[test]
    fn actions_parse_and_print() {
        assert_eq!(Action::parse(None), Ok(Action::Log));
        assert_eq!(Action::parse(Some("skip")), Ok(Action::Skip));
        assert_eq!(Action::parse(Some("return -1")), Ok(Action::Return(-1)));
        assert_eq!(Action::parse(Some("return 0x10")), Ok(Action::Return(16)));
        let h = Action::parse(Some("my hooks.dll!OnCenter")).unwrap();
        assert_eq!(h.to_string(), "my hooks.dll!OnCenter");
        // Negative: anything else is refused, never guessed.
        for bad in [
            "Hook_CenterWindow",
            "return",
            "return yes",
            "hooks.exe!F",
            "hooks.dll!",
            "hooks.dll!1F",
            "hooks.dll!a-b",
        ] {
            assert!(Action::parse(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn hooks_are_listed_for_their_own_build_with_decoded_arguments() {
        let m = manifest(vec![
            hook(
                "CenterWindow",
                "v2",
                Some(0x118d0),
                Some("skip"),
                Some("BOOL CenterWindow(HWND hWnd)"),
            ),
            hook(
                "Title",
                "v2",
                Some(0x2000),
                None,
                Some("int Title(const wchar_t* text, double scale, char* tag)"),
            ),
        ]);
        let (c, skipped) = config(&[m], &[]).unwrap();
        assert!(skipped.is_empty());
        let cw = &c.hooks[0];
        assert_eq!(cw.build, BuildId("v2".into()));
        assert_eq!(cw.action, "skip");
        assert_eq!(cw.ret, Some(ValueType::Int(4)));
        assert_eq!(cw.args[0].value, ValueType::Pointer);
        assert_eq!(cw.args[0].slot, ArgSlot::Int(0));
        let t = &c.hooks[1];
        assert_eq!(t.action, "log");
        assert_eq!(t.args[0].show, Some(Show::Wstring));
        assert_eq!(t.args[1].slot, ArgSlot::Vector(1));
        assert_eq!(t.args[2].show, Some(Show::Cstring));
        // The config round-trips through TOML, as the host reads it.
        let text = toml::to_string_pretty(&c).unwrap();
        assert_eq!(toml::from_str::<HostConfig>(&text).unwrap(), c);
    }

    #[test]
    fn a_hook_left_in_review_stays_on_its_verified_build() {
        // The repaired manifest left `B` bound to v1 (in review): it's listed for v1 only, never for v2.
        let v1 = manifest(vec![hook("B", "v1", Some(0x10), None, None)]);
        let v2 = manifest(vec![
            hook("A", "v2", Some(0x120), None, None),
            hook("B", "v1", Some(0x10), None, None),
            hook("C", "v2", None, None, None),
        ]);
        let (c, skipped) = config(&[v1, v2], &[]).unwrap();
        let listed: Vec<(&str, &str)> = c
            .hooks
            .iter()
            .map(|h| (h.name.as_str(), h.build.0.as_str()))
            .collect();
        assert_eq!(listed, vec![("B", "v1"), ("A", "v2")]);
        assert_eq!(skipped[0].name, "C");
        // Negative: the same hook and build with a different RVA is an error, not a pick.
        let other = manifest(vec![hook("B", "v1", Some(0x20), None, None)]);
        let v1 = manifest(vec![hook("B", "v1", Some(0x10), None, None)]);
        assert!(config(&[v1, other], &[]).is_err());
    }

    #[test]
    fn a_pdb_signature_stands_in_for_a_missing_prototype() {
        let mut f = FunctionFeatures {
            rva: Rva(0x10),
            size: 64,
            name: None,
            name_source: None,
            normalized_hash: None,
            mnemonic_hash: None,
            basic_blocks: None,
            edges: None,
            callees: vec![],
            strings: vec![],
            constants: vec![],
            imports: vec![],
            data_refs: vec![],
            code_refs: vec![],
            thunk_to: None,
            signature: None,
            inferred_args: None,
            inferred_arg_classes: vec![],
            arg_accesses: vec![],
            mnemonic_counts: Default::default(),
            entry: None,
            pseudocode: None,
        };
        f.signature = Some(FunctionSignature {
            calling_convention: Some("__cdecl".into()),
            return_type: Some("int".into()),
            params: vec![Param {
                name: None,
                ty: "struct HWND__*".into(),
            }],
        });
        let analysis = AnalysisExport {
            schema_version: ANALYSIS_SCHEMA_VERSION,
            build: BuildInfo {
                id: BuildId("v1".into()),
                file_name: "t.exe".into(),
                version: None,
                machine: Machine::X64,
                pdb: None,
            },
            producer: Producer {
                tool: "t".into(),
                version: "0".into(),
            },
            features_version: None,
            functions: vec![f],
            code_tables: vec![],
            types: vec![],
            globals: vec![],
            data_symbols: vec![],
            pointer_aliases: vec![],
        };
        let m = manifest(vec![hook("CenterWindow", "v1", Some(0x10), None, None)]);
        let (c, _) = config(std::slice::from_ref(&m), std::slice::from_ref(&analysis)).unwrap();
        assert_eq!(
            c.hooks[0].prototype.as_deref(),
            Some("int CenterWindow(struct HWND__*)")
        );
        assert_eq!(c.hooks[0].args[0].value, ValueType::Pointer);
        // Negative: another build's analysis isn't used: no prototype, so the log shows raw registers.
        let mut other = analysis;
        other.build.id = BuildId("v2".into());
        let (c, _) = config(&[m], &[other]).unwrap();
        assert_eq!(c.hooks[0].prototype, None);
        assert!(c.hooks[0].args.is_empty());
    }

    #[test]
    fn built_in_actions_refuse_what_the_thunk_cannot_do() {
        // Negative: `return` for a floating-point result, and more parameters than the thunk forwards.
        let m = manifest(vec![hook(
            "F",
            "v1",
            Some(0x10),
            Some("return 1"),
            Some("double F(int a)"),
        )]);
        assert!(config(&[m], &[]).is_err());
        let many: Vec<String> = (0..13).map(|i| format!("int a{i}")).collect();
        let proto = format!("int G({})", many.join(", "));
        let m = manifest(vec![hook("G", "v1", Some(0x10), Some("log"), Some(&proto))]);
        assert!(config(&[m], &[]).is_err());
        // A handler is attached directly: no limit.
        let m = manifest(vec![hook(
            "G",
            "v1",
            Some(0x10),
            Some("h.dll!G"),
            Some(&proto),
        )]);
        assert!(config(&[m], &[]).is_ok());
        // Negative: an unknown action stops the whole config.
        let m = manifest(vec![hook("H", "v1", Some(0x10), Some("Hook_H"), None)]);
        assert!(config(&[m], &[]).unwrap_err().contains("unknown action"));
    }
}
