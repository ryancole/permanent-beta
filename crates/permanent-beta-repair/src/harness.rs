//! Record spec for the recording hook DLL (design §7.3, `pbeta harness-spec`): from the hook manifest, each hook's
//! prototype and the build's PDB struct layouts, what to capture per call.
//!
//! Per parameter: its Win64 slot, how the value travels (integer, float, pointer) and its width, and for a
//! pointer what it points to:
//! - a struct the PDB lays out: that many bytes (`fixed`);
//! - a scalar or a pointer (`int*`, `unsigned short*`, `T**`): `array`, the whole heap block holding it, since the
//!   prototype can't say whether it's one value or an element of an array (zlib's `inflate_table(..., unsigned
//!   short* lens, ...)`), and otherwise its own bytes;
//! - `const char*` / `char*`: a NUL-terminated string (`cstring`);
//! - a byte pointer (`char*`, `unsigned char*`, `void*`, …) directly followed by an integer whose name says it's
//!   a length (`len`, `size`, `cap`, `n`, …): that many bytes (`sized`). **[Guess]**: the names are the only
//!   evidence. A wrong guess captures too little (replay reads uncaptured memory: inconclusive), never too much:
//!   the recorder reads at most `max` bytes and survives unreadable memory.
//! - anything else (a struct without a layout, `T***`, an unknown typedef): nothing. A replay that reads it is
//!   inconclusive.
//!
//! Per hook, the globals to capture with each call: those the function, or anything it calls directly or
//! indirectly, refers to (the analysis's `data_refs` that fall in a PDB-named global; `__security_cookie` is
//! left out, replay gives it a fixed value). Calls through pointers aren't followed, so a global only such a
//! callee reads isn't listed and a replay that reads it is inconclusive.
//!
//! Redaction ([`redact`], `pbeta harness-spec --redact hook.param`): an argument or global marked `redact` is never
//! recorded, nor any import call's memory that overlaps it. `import_memory = false` records import calls without
//! their memory, so data derived from the hook's (a receipt formatted from a customer name) can't reach the
//! recording through one either.
//!
//! The spec is TOML, meant to be read and edited before recording.

use crate::prototype::Prototype;
use permanent_beta_model::{
    AnalysisExport, ArgSlot, ArgSpec, CaptureKind, GlobalSpec, HarnessSpec, HookManifest,
    HookRecordSpec, PointerField, Rva, SkippedHook, ValueType,
};
use std::collections::BTreeSet;

/// Globals replay already handles and that aren't captured.
const UNCAPTURED_GLOBALS: [&str; 1] = ["__security_cookie"];

/// Default cap on distinct cases per hook. **[Guess]**
pub const DEFAULT_MAX_CASES: u32 = 32;
/// Pointers followed from the arguments' memory by default: a stream struct, its state, the state's buffers
/// (zlib's `z_stream` → `internal_state` → window). **[Guess]**
pub const DEFAULT_POINTER_DEPTH: u32 = 2;
/// Most bytes captured for a C string. **[Guess]**
pub const CSTRING_MAX: u64 = 4096;
/// Most bytes captured for a buffer sized by another argument. **[Guess]**
pub const SIZED_MAX: u64 = 64 * 1024;

/// The spec for every hook of `manifest` bound to `build`'s build. `build` should be analyzed with `--pdb`, or
/// no struct gets a layout (its pointers capture nothing).
pub fn spec(manifest: &HookManifest, build: &AnalysisExport, max_cases: u32) -> HarnessSpec {
    let mut out = HarnessSpec {
        build: build.build.id.clone(),
        max_cases,
        import_memory: true,
        pointer_depth: DEFAULT_POINTER_DEPTH,
        hooks: Vec::new(),
        skipped: Vec::new(),
        layouts: Vec::new(),
        pointers: Vec::new(),
    };
    for hook in &manifest.hooks {
        let skip = |reason: String| SkippedHook {
            name: hook.name.clone(),
            reason,
        };
        if hook.target.build != build.build.id {
            out.skipped.push(skip(format!(
                "bound to build {}, not this one",
                hook.target.build
            )));
            continue;
        }
        let Some(rva) = hook.target.rva else {
            out.skipped.push(skip("no RVA".into()));
            continue;
        };
        let Some(text) = hook.prototype.as_deref() else {
            out.skipped.push(skip("no prototype".into()));
            continue;
        };
        let Some(proto) = Prototype::parse(text) else {
            out.skipped
                .push(skip(format!("can't parse the prototype {text:?}")));
            continue;
        };
        let mut args = Vec::new();
        for (i, p) in proto.params.iter().enumerate() {
            let value = value_type(&p.ty);
            let index = i as u32;
            let slot = ArgSlot::for_param(index, value.in_vector_register());
            let mut arg = ArgSpec {
                index,
                slot,
                name: p.name.clone(),
                ty: p.ty.clone(),
                value,
                capture: CaptureKind::None,
                size: None,
                layout: None,
                len_slot: None,
                max: None,
                redact: false,
            };
            if value == ValueType::Pointer {
                let next = proto.params.get(i + 1);
                match pointee(&p.ty) {
                    Pointee::Bytes { cstring } => {
                        let len = next.filter(|n| {
                            matches!(value_type(&n.ty), ValueType::Int(_))
                                && n.name.as_deref().is_some_and(is_length_name)
                        });
                        if len.is_some() {
                            arg.capture = CaptureKind::Sized;
                            arg.len_slot = Some(ArgSlot::for_param(index + 1, false));
                            arg.max = Some(SIZED_MAX);
                        } else if cstring {
                            arg.capture = CaptureKind::Cstring;
                            arg.max = Some(CSTRING_MAX);
                        }
                    }
                    Pointee::Scalar(size) => {
                        arg.capture = CaptureKind::Array;
                        arg.size = Some(size);
                    }
                    Pointee::Named(name) => {
                        if let Some(layout) = build.type_layout(&name) {
                            arg.capture = CaptureKind::Fixed;
                            arg.size = Some(layout.size);
                            arg.layout = Some(name.clone());
                            if out.layout(&name).is_none() {
                                out.layouts.push(layout.clone());
                            }
                        }
                    }
                    // A pointer to a pointer (`code** table`, `char** argv`): the pointers, as an array; what
                    // they point to isn't followed.
                    Pointee::Unknown if is_pointer_to_pointer(&p.ty) => {
                        arg.capture = CaptureKind::Array;
                        arg.size = Some(8);
                    }
                    Pointee::Unknown => {}
                }
            }
            args.push(arg);
        }
        out.hooks.push(HookRecordSpec {
            name: hook.name.clone(),
            rva,
            prototype: text.to_owned(),
            ret: return_type(&proto),
            stack_args: proto.params.len().saturating_sub(4) as u32,
            args,
            globals: reachable_globals(build, rva),
        });
    }
    add_pointer_fields(&mut out, build, 0);
    out
}

/// The named globals the function at `rva` and its direct and indirect callees refer to, by RVA.
fn reachable_globals(build: &AnalysisExport, rva: Rva) -> Vec<GlobalSpec> {
    let mut seen: BTreeSet<Rva> = BTreeSet::new();
    let mut todo = vec![rva];
    let mut out: Vec<GlobalSpec> = Vec::new();
    while let Some(r) = todo.pop() {
        if !seen.insert(r) {
            continue;
        }
        let Some(f) = build.function(r) else {
            continue;
        };
        for d in &f.data_refs {
            if let Some(g) = build.global_at(*d)
                && !UNCAPTURED_GLOBALS.contains(&g.name.as_str())
                && !out.iter().any(|o| o.name == g.name)
            {
                out.push(GlobalSpec {
                    name: g.name.clone(),
                    rva: g.rva,
                    size: g.size,
                    redact: false,
                });
            }
        }
        todo.extend(f.callees.iter().copied());
    }
    out.sort_by_key(|g| g.rva);
    out
}

/// Most struct layouts the spec follows pointers into. **[Guess]**
pub const MAX_POINTER_LAYOUTS: usize = 64;

/// The pointer fields of every layout in the spec, adding the layouts of the structs they point to (and theirs,
/// up to [`MAX_POINTER_LAYOUTS`]). A field pointing to bytes, a scalar or `void` is followed but not scanned; a
/// function pointer or a type without a layout isn't followed.
fn add_pointer_fields(out: &mut HarnessSpec, build: &AnalysisExport, from: usize) {
    let mut i = from;
    while i < out.layouts.len() {
        let layout = out.layouts[i].clone();
        i += 1;
        for f in &layout.fields {
            if f.size != 8 || f.bits.is_some() || value_type(&f.ty) != ValueType::Pointer {
                continue;
            }
            let target = match pointee(&f.ty) {
                Pointee::Bytes { .. } | Pointee::Scalar(_) => None,
                Pointee::Named(name) => match build.type_layout(&name) {
                    Some(t) => {
                        if out.layout(&name).is_none() {
                            if out.layouts.len() >= MAX_POINTER_LAYOUTS {
                                continue;
                            }
                            out.layouts.push(t.clone());
                        }
                        Some(name)
                    }
                    None => continue,
                },
                Pointee::Unknown => continue,
            };
            out.pointers.push(PointerField {
                layout: layout.name.clone(),
                offset: f.offset,
                target,
            });
        }
    }
}

/// `layout.field=Target`: the pointer field may also point to a `Target`, a layout of `build` no prototype leads
/// to (code casts the opaque pointer: zlib's `z_stream_s.state`, declared `internal_state*`, is a `struct
/// inflate_state` in inflate). Added as a second [`PointerField`] after the declared one, with `Target`'s layout
/// and its own pointer fields. The recorder takes a heap block as a struct only when the block is exactly that
/// struct's size, never one larger than the block; where it can't tell (no heap block), the declared type
/// comes first and wins. `Err` if the layout, the field or `Target` isn't known, or the field isn't a pointer.
pub fn pointer_alias(
    spec: &mut HarnessSpec,
    build: &AnalysisExport,
    what: &str,
) -> Result<(), String> {
    let bad = |why: &str| format!("{what:?}: {why}");
    let (field, target) = what
        .split_once('=')
        .ok_or_else(|| bad("expected layout.field=Target"))?;
    let (layout, field) = field
        .split_once('.')
        .ok_or_else(|| bad("expected layout.field=Target"))?;
    let l = spec
        .layout(layout)
        .ok_or_else(|| bad(&format!("the spec captures no {layout}")))?;
    let f = l
        .fields
        .iter()
        .find(|f| f.name == field)
        .ok_or_else(|| bad(&format!("{layout} has no field {field}")))?;
    if f.size != 8 || value_type(&f.ty) != ValueType::Pointer {
        return Err(bad(&format!("{layout}.{field} isn't a pointer")));
    }
    let offset = f.offset;
    let t = build
        .type_layout(target)
        .ok_or_else(|| {
            bad(&format!(
                "no layout of {target} (pbeta analyze --pdb --type {target})"
            ))
        })?
        .clone();
    let entry = PointerField {
        layout: layout.to_owned(),
        offset,
        target: Some(target.to_owned()),
    };
    if spec.pointers.contains(&entry) {
        return Ok(());
    }
    spec.pointers.push(entry);
    if spec.layout(target).is_none() {
        let from = spec.layouts.len();
        spec.layouts.push(t);
        add_pointer_fields(spec, build, from);
    }
    Ok(())
}

/// Marks `what` as never recorded: `hook.param` (a parameter by name or 0-based position) or `hook.global` (a
/// global the hook's spec captures, by name). `Err` if no hook has it.
pub fn redact(spec: &mut HarnessSpec, what: &str) -> Result<(), String> {
    let (hook, item) = what
        .split_once('.')
        .ok_or_else(|| format!("{what:?}: expected hook.param or hook.global"))?;
    let h = spec
        .hooks
        .iter_mut()
        .find(|h| h.name == hook)
        .ok_or_else(|| format!("{what:?}: no hook {hook} in the spec"))?;
    let index: Option<u32> = item.parse().ok();
    if let Some(a) = h
        .args
        .iter_mut()
        .find(|a| a.name.as_deref() == Some(item) || Some(a.index) == index)
    {
        a.redact = true;
        return Ok(());
    }
    if let Some(g) = h.globals.iter_mut().find(|g| g.name == item) {
        g.redact = true;
        return Ok(());
    }
    Err(format!(
        "{what:?}: {hook} has no parameter or captured global {item}"
    ))
}

fn return_type(proto: &Prototype) -> ValueType {
    let ty: Vec<&str> = proto
        .head
        .split_whitespace()
        .filter(|w| !w.starts_with("__") && *w != "static" && *w != "inline")
        .collect();
    value_type(&ty.join(" "))
}

/// Words that don't change how a value travels.
fn significant_words(ty: &str) -> Vec<&str> {
    ty.split(|c: char| c.is_whitespace())
        .filter(|w| {
            !w.is_empty()
                && !matches!(
                    *w,
                    "const" | "volatile" | "struct" | "class" | "union" | "signed" | "__restrict"
                )
                && !w.starts_with("__") // calling conventions
        })
        .collect()
}

/// How a parameter of type `ty` travels in Win64, and how wide it is.
pub fn value_type(ty: &str) -> ValueType {
    if ty.contains('*') || ty.contains('&') || ty.contains('[') {
        return ValueType::Pointer;
    }
    scalar(&significant_words(ty).join(" ")).unwrap_or(ValueType::Unknown)
}

/// Built-in and common fixed-width scalar types (LLP64: `long` is 4 bytes, MSVC's `long double` is 8).
fn scalar(ty: &str) -> Option<ValueType> {
    use ValueType::{Float, Int, Void};
    Some(match ty {
        "void" => Void,
        "bool" | "char" | "unsigned char" | "int8_t" | "uint8_t" | "BYTE" | "BOOLEAN" => Int(1),
        "short" | "unsigned short" | "short int" | "unsigned short int" | "int16_t"
        | "uint16_t" | "wchar_t" | "WORD" => Int(2),
        "int" | "unsigned" | "unsigned int" | "long" | "unsigned long" | "long int"
        | "unsigned long int" | "int32_t" | "uint32_t" | "DWORD" | "BOOL" | "LONG" | "UINT" => {
            Int(4)
        }
        "long long"
        | "unsigned long long"
        | "long long int"
        | "unsigned long long int"
        | "__int64"
        | "int64_t"
        | "uint64_t"
        | "size_t"
        | "ptrdiff_t"
        | "intptr_t"
        | "uintptr_t"
        | "ssize_t"
        | "SIZE_T"
        | "DWORD64"
        | "ULONG_PTR"
        | "LONG_PTR" => Int(8),
        "float" => Float(4),
        "double" | "long double" => Float(8),
        _ => return None,
    })
}

enum Pointee {
    /// A byte type (`char`, `unsigned char`, `void`, …); `cstring` for plain `char`.
    Bytes {
        cstring: bool,
    },
    Scalar(u64),
    /// A struct, class or union name to look up in the PDB layouts.
    Named(String),
    Unknown,
}

fn pointee(ty: &str) -> Pointee {
    if ty.contains('&') || ty.contains('[') || ty.matches('*').count() != 1 {
        return Pointee::Unknown;
    }
    let base = ty.replace('*', " ");
    let words = significant_words(&base);
    let joined = words.join(" ");
    match joined.as_str() {
        "char" => return Pointee::Bytes { cstring: true },
        "unsigned char" | "uint8_t" | "int8_t" | "void" | "BYTE" => {
            return Pointee::Bytes { cstring: false };
        }
        _ => {}
    }
    if let Some(v) = scalar(&joined) {
        return v
            .width()
            .map_or(Pointee::Unknown, |w| Pointee::Scalar(u64::from(w)));
    }
    match words.as_slice() {
        [name]
            if name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':') =>
        {
            Pointee::Named((*name).to_owned())
        }
        _ => Pointee::Unknown,
    }
}

/// `T**`, and nothing else (no references, arrays or more stars).
fn is_pointer_to_pointer(ty: &str) -> bool {
    !ty.contains('&') && !ty.contains('[') && ty.matches('*').count() == 2
}

/// Parameter names that say "the byte count of the previous parameter". **[Guess]**
fn is_length_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "n" | "len" | "length" | "size" | "cap" | "capacity" | "count" | "bytes" | "nbytes" | "cb"
    ) || ["len", "size", "_cap", "_bytes"]
        .iter()
        .any(|s| n.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{
        BuildId, Criticality, FieldLayout, HookSpec, Rva, TargetLocator, TypeLayout,
    };

    fn export(id: &str, types: Vec<TypeLayout>) -> AnalysisExport {
        let mut e: AnalysisExport = serde_json::from_value(serde_json::json!({
            "schema_version": permanent_beta_model::ANALYSIS_SCHEMA_VERSION,
            "build": { "id": id, "file_name": "t.exe", "version": null, "machine": "x64", "pdb": null },
            "producer": { "tool": "test", "version": "0" },
            "functions": [],
        }))
        .unwrap();
        e.types = types;
        e
    }

    fn order() -> TypeLayout {
        let f = |name: &str, offset, size, ty: &str| FieldLayout {
            name: name.into(),
            offset,
            size,
            ty: ty.into(),
            bits: None,
        };
        TypeLayout {
            name: "Order".into(),
            size: 0x4c,
            union: false,
            fields: vec![
                f("id", 0, 4, "int"),
                f("count", 4, 4, "int"),
                f("skus", 8, 32, "int[8]"),
                f("qtys", 0x28, 32, "int[8]"),
                f("total", 0x48, 4, "int"),
            ],
        }
    }

    fn manifest(hooks: &[(&str, Option<&str>, &str)]) -> HookManifest {
        HookManifest {
            hooks: hooks
                .iter()
                .enumerate()
                .map(|(i, (name, proto, build))| HookSpec {
                    name: (*name).into(),
                    detour: None,
                    criticality: Criticality::Normal,
                    prototype: proto.map(str::to_owned),
                    trial: false,
                    target: TargetLocator {
                        build: BuildId((*build).into()),
                        rva: Some(Rva(0x1000 + 0x10 * i as u64)),
                        symbol: None,
                        pattern: None,
                    },
                })
                .collect(),
        }
    }

    fn the_hook_apps_spec() -> HarnessSpec {
        let m = manifest(&[
            ("price_lookup", Some("int price_lookup(int sku)"), "v1"),
            (
                "order_add",
                Some("int order_add(Order* o, int sku, int qty)"),
                "v1",
            ),
            (
                "format_receipt",
                Some(
                    "int format_receipt(char* buf, int cap, const Order* o, const char* customer)",
                ),
                "v1",
            ),
            (
                "checksum",
                Some("unsigned checksum(const unsigned char* data, int len)"),
                "v1",
            ),
            (
                "log_event",
                Some("void log_event(const char* msg, int code)"),
                "v1",
            ),
            (
                "scale",
                Some("double scale(double x, float f, int* out, long long k, double y)"),
                "v1",
            ),
        ]);
        spec(&m, &export("v1", vec![order()]), DEFAULT_MAX_CASES)
    }

    #[test]
    fn scalars_travel_in_their_registers() {
        let s = the_hook_apps_spec();
        let h = s.hook("price_lookup").unwrap();
        assert_eq!(h.ret, ValueType::Int(4));
        assert_eq!(h.args[0].slot, ArgSlot::Int(0));
        assert_eq!(h.args[0].capture, CaptureKind::None);
        let h = s.hook("scale").unwrap();
        assert_eq!(h.ret, ValueType::Float(8));
        let slots: Vec<String> = h.args.iter().map(|a| a.slot.to_string()).collect();
        assert_eq!(slots, ["xmm0", "xmm1", "r8", "r9", "stack+0x28"]);
        assert_eq!(h.stack_args, 1);
        // `int* out`: a scalar pointee, 4 bytes, or the heap block it's an element of.
        assert_eq!(
            (h.args[2].capture, h.args[2].size),
            (CaptureKind::Array, Some(4))
        );
        assert_eq!(s.hook("log_event").unwrap().ret, ValueType::Void);
    }

    #[test]
    fn struct_pointers_capture_the_pdb_layout() {
        let s = the_hook_apps_spec();
        let a = &s.hook("order_add").unwrap().args[0];
        assert_eq!(
            (a.capture, a.size, a.layout.as_deref()),
            (CaptureKind::Fixed, Some(0x4c), Some("Order"))
        );
        assert_eq!(s.layouts, vec![order()], "each layout once");
    }

    #[test]
    fn strings_and_sized_buffers() {
        let s = the_hook_apps_spec();
        let fr = s.hook("format_receipt").unwrap();
        assert_eq!(fr.args[0].capture, CaptureKind::Sized, "char* buf, int cap");
        assert_eq!(fr.args[0].len_slot, Some(ArgSlot::Int(1)));
        assert_eq!(fr.args[3].capture, CaptureKind::Cstring);
        let c = s.hook("checksum").unwrap();
        assert_eq!(c.args[0].capture, CaptureKind::Sized);
        assert_eq!(c.args[0].max, Some(SIZED_MAX));
        // `const char* msg, int code`: `code` isn't a length, so it's a string.
        assert_eq!(
            s.hook("log_event").unwrap().args[0].capture,
            CaptureKind::Cstring
        );
    }

    /// zlib's shape: a stream whose `state` is declared as deflate's struct, and inflate's struct no
    /// prototype mentions.
    fn zlib_like() -> AnalysisExport {
        let f = |name: &str, offset, size, ty: &str| FieldLayout {
            name: name.into(),
            offset,
            size,
            ty: ty.into(),
            bits: None,
        };
        let l = |name: &str, size, fields| TypeLayout {
            name: name.into(),
            size,
            union: false,
            fields,
        };
        export(
            "v1",
            vec![
                l(
                    "z_stream_s",
                    0x58,
                    vec![
                        f("avail_in", 8, 4, "unsigned int"),
                        f("state", 0x28, 8, "struct internal_state*"),
                    ],
                ),
                l(
                    "internal_state",
                    0x1718,
                    vec![f("window", 0x50, 8, "unsigned char*")],
                ),
                l(
                    "inflate_state",
                    0x1bf0,
                    vec![
                        f("strm", 0, 8, "struct z_stream_s*"),
                        f("window", 0x40, 8, "unsigned char*"),
                    ],
                ),
            ],
        )
    }

    #[test]
    fn a_pointer_field_can_be_aliased_to_another_struct() {
        let build = zlib_like();
        let m = manifest(&[(
            "inflate",
            Some("int inflate(z_stream_s* strm, int flush)"),
            "v1",
        )]);
        let mut s = spec(&m, &build, 8);
        assert!(
            s.layout("inflate_state").is_none(),
            "no prototype leads there"
        );
        pointer_alias(&mut s, &build, "z_stream_s.state=inflate_state").unwrap();
        let state: Vec<Option<&str>> = s
            .pointers
            .iter()
            .filter(|p| p.layout == "z_stream_s" && p.offset == 0x28)
            .map(|p| p.target.as_deref())
            .collect();
        assert_eq!(
            state,
            [Some("internal_state"), Some("inflate_state")],
            "declared first"
        );
        // inflate_state's own pointer fields are followed too.
        assert!(
            s.pointers
                .iter()
                .any(|p| p.layout == "inflate_state" && p.offset == 0x40 && p.target.is_none())
        );
        // Twice is once.
        let n = s.pointers.len();
        pointer_alias(&mut s, &build, "z_stream_s.state=inflate_state").unwrap();
        assert_eq!(s.pointers.len(), n);
    }

    #[test]
    fn a_bad_pointer_alias_is_refused() {
        // Negative: an unknown layout, field or target, a field that isn't a pointer, no `=`.
        let build = zlib_like();
        let m = manifest(&[(
            "inflate",
            Some("int inflate(z_stream_s* strm, int flush)"),
            "v1",
        )]);
        let mut s = spec(&m, &build, 8);
        for (what, why) in [
            ("gz_state.state=inflate_state", "captures no gz_state"),
            ("z_stream_s.opaque=inflate_state", "no field opaque"),
            (
                "z_stream_s.state=deflate_state",
                "no layout of deflate_state",
            ),
            ("z_stream_s.avail_in=inflate_state", "isn't a pointer"),
            ("z_stream_s.state", "expected"),
        ] {
            let got = pointer_alias(&mut s, &build, what);
            assert!(matches!(&got, Err(e) if e.contains(why)), "{what}: {got:?}");
        }
    }

    #[test]
    fn arrays_of_scalars_and_pointers() {
        // zlib's inflate_table: every pointer may index an array in inflate's state.
        let m = manifest(&[(
            "inflate_table",
            Some(
                "int inflate_table(int type, unsigned short* lens, unsigned int codes, code** table, unsigned int* bits, unsigned short* work)",
            ),
            "v1",
        )]);
        let s = spec(&m, &export("v1", vec![]), 8);
        let got: Vec<(CaptureKind, Option<u64>)> = s.hooks[0]
            .args
            .iter()
            .map(|a| (a.capture, a.size))
            .collect();
        use CaptureKind::{Array, None as Nothing};
        assert_eq!(
            got,
            [
                (Nothing, None),
                (Array, Some(2)),
                (Nothing, None),
                (Array, Some(8)),
                (Array, Some(4)),
                (Array, Some(2)),
            ]
        );
        // Negative: three stars, and a reference to a pointer, capture nothing.
        assert!(!is_pointer_to_pointer("char***"));
        assert!(!is_pointer_to_pointer("char*&"));
        assert!(is_pointer_to_pointer("const char* const*"));
    }

    #[test]
    fn unknown_pointees_capture_nothing() {
        // Negative: no PDB layout for Order, a pointer to a pointer to a pointer, an unknown typedef, a byte
        // buffer with no length after it.
        let m = manifest(&[
            ("a", Some("int a(Order* o)"), "v1"),
            ("b", Some("int b(char*** argv)"), "v1"),
            ("c", Some("int c(HANDLE_T* h)"), "v1"),
            ("d", Some("int d(unsigned char* p, int flags)"), "v1"),
        ]);
        let s = spec(&m, &export("v1", vec![]), 8);
        for h in &s.hooks {
            assert_eq!(h.args[0].capture, CaptureKind::None, "{}", h.name);
        }
        assert!(s.layouts.is_empty());
        // A struct by value has no single-register value type.
        assert_eq!(value_type("Order"), ValueType::Unknown);
    }

    #[test]
    fn hooks_that_cant_be_recorded_are_listed() {
        // Negative: another build's hook, no prototype, an unparsable prototype.
        let m = manifest(&[
            ("other", Some("int f(int)"), "v0"),
            ("none", None, "v1"),
            ("bad", Some("int (*f)(int)"), "v1"),
        ]);
        let s = spec(&m, &export("v1", vec![]), 8);
        assert!(s.hooks.is_empty());
        let names: Vec<&str> = s.skipped.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["other", "none", "bad"]);
    }

    #[test]
    fn globals_are_collected_through_callees() {
        let mut e = export("v1", vec![]);
        let func = |rva: u64, callees: &[u64], refs: &[u64]| {
            let mut f: permanent_beta_model::FunctionFeatures = serde_json::from_value(
                serde_json::json!({"rva": format!("{rva:#x}"), "size": 16, "name": null, "name_source": null,
                    "normalized_hash": null, "mnemonic_hash": null, "basic_blocks": null, "edges": null,
                    "signature": null}),
            )
            .unwrap();
            f.callees = callees.iter().map(|&c| Rva(c)).collect();
            f.data_refs = refs.iter().map(|&d| Rva(d)).collect();
            f
        };
        // The hook (0x1000) calls 0x1100, which calls 0x1200 (reads the printf options) and recurses into 0x1100.
        e.functions = vec![
            func(0x1000, &[0x1100], &[0x4000]),
            func(0x1100, &[0x1200, 0x1100], &[0x4088]),
            func(0x1200, &[], &[0x4080, 0x4090]),
            func(0x1300, &[], &[0x40a0]),
        ];
        let g = |name: &str, rva, size| permanent_beta_model::GlobalVar {
            name: name.into(),
            rva: Rva(rva),
            size,
            ty: "int".into(),
        };
        e.globals = vec![
            g("__security_cookie", 0x4000, 8),
            g("__local_stdio_printf_options::_OptionsStorage", 0x4080, 8),
            g("g_events", 0x4088, 4),
            g("g_other", 0x40a0, 4),
        ];
        let m = manifest(&[("hook", Some("int hook(int x)"), "v1")]);
        let s = spec(&m, &e, 8);
        let names: Vec<&str> = s.hooks[0].globals.iter().map(|g| g.name.as_str()).collect();
        // Negative: the security cookie, an unnamed reference (0x4090) and a global only an uncalled function
        // reads aren't listed.
        assert_eq!(
            names,
            ["__local_stdio_printf_options::_OptionsStorage", "g_events"]
        );
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.contains("[[hook.global]]"), "{text}");
        assert_eq!(toml::from_str::<HarnessSpec>(&text).unwrap(), s);
    }

    #[test]
    fn redaction_marks_parameters_and_globals() {
        let mut s = the_hook_apps_spec();
        redact(&mut s, "format_receipt.customer").unwrap();
        redact(&mut s, "format_receipt.0").unwrap();
        let fr = s.hook("format_receipt").unwrap();
        let redacted: Vec<u32> = fr
            .args
            .iter()
            .filter(|a| a.redact)
            .map(|a| a.index)
            .collect();
        assert_eq!(redacted, [0, 3]);
        // Negative: other hooks and parameters are untouched; unknown names are refused, not ignored.
        assert!(
            s.hooks
                .iter()
                .filter(|h| h.name != "format_receipt")
                .all(|h| h.args.iter().all(|a| !a.redact))
        );
        for bad in ["format_receipt.nobody", "nobody.customer", "format_receipt"] {
            assert!(redact(&mut s, bad).is_err(), "{bad}");
        }
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.contains("redact = true"), "{text}");
        assert!(text.contains("import_memory = true"), "{text}");
        let depth = format!("pointer_depth = {DEFAULT_POINTER_DEPTH}\n");
        assert!(text.contains(&depth), "{text}");
        assert_eq!(toml::from_str::<HarnessSpec>(&text).unwrap(), s);
        // A spec written before redaction and pointer depth existed reads as nothing redacted, import memory on,
        // no pointers followed (what those recorders did).
        let old = text
            .replace("redact = true", "redact = false")
            .replace("import_memory = true\n", "")
            .replace(&depth, "");
        let parsed: HarnessSpec = toml::from_str(&old).unwrap();
        assert!(parsed.import_memory);
        assert_eq!(parsed.pointer_depth, 0);
        assert!(
            parsed
                .hooks
                .iter()
                .all(|h| h.args.iter().all(|a| !a.redact))
        );
    }

    #[test]
    fn the_spec_round_trips_through_toml() {
        let s = the_hook_apps_spec();
        let text = toml::to_string_pretty(&s).unwrap();
        assert!(text.contains("[[hook.arg]]"), "{text}");
        assert!(text.contains("slot = \"rcx\""), "{text}");
        assert_eq!(toml::from_str::<HarnessSpec>(&text).unwrap(), s);
    }

    #[test]
    fn pointer_fields_are_followed_by_type() {
        let f = |name: &str, offset, size, ty: &str| FieldLayout {
            name: name.into(),
            offset,
            size,
            ty: ty.into(),
            bits: None,
        };
        let stream = TypeLayout {
            name: "stream".into(),
            size: 0x30,
            union: false,
            fields: vec![
                f("next_in", 0, 8, "unsigned char*"),
                f("avail", 8, 4, "unsigned int"),
                f("state", 0x10, 8, "struct state*"),
                f("alloc", 0x18, 8, "void* (*)(void*, unsigned int)"),
                f("other", 0x20, 8, "struct nobody*"),
                f("opaque", 0x28, 8, "void*"),
            ],
        };
        let state = TypeLayout {
            name: "state".into(),
            size: 0x10,
            union: false,
            fields: vec![
                f("strm", 0, 8, "struct stream*"),
                f("window", 8, 8, "unsigned char*"),
            ],
        };
        let m = manifest(&[(
            "deflate",
            Some("int deflate(stream* strm, int flush)"),
            "v1",
        )]);
        let s = spec(&m, &export("v1", vec![stream, state]), DEFAULT_MAX_CASES);
        let names: Vec<&str> = s.layouts.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            names,
            ["stream", "state"],
            "the state is reached through a pointer field"
        );
        let got: Vec<(&str, u64, Option<&str>)> = s
            .pointers
            .iter()
            .map(|p| (p.layout.as_str(), p.offset, p.target.as_deref()))
            .collect();
        // Negative: the function pointer and the pointer to a type without a layout aren't followed; a byte
        // buffer and void* are followed as bytes (captured, never scanned for more pointers).
        assert_eq!(
            got,
            [
                ("stream", 0, None),
                ("stream", 0x10, Some("state")),
                ("stream", 0x28, None),
                ("state", 0, Some("stream")),
                ("state", 8, None),
            ]
        );
    }
}
