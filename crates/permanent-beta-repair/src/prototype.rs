//! Prototype adaptation proposals (design §7.2): when the new function reads more register arguments than the
//! hook's prototype declares, propose the longer prototype and a shim that keeps the existing detour working.
//!
//! Evidence is the analyzer's inferred register arguments, a lower bound: unused trailing parameters and stack
//! arguments are invisible, so only *added* register parameters (slots 1–4) are proposed, never removed ones.
//! An added parameter's type is a guess from the register the code reads: `intptr_t` for rcx/rdx/r8/r9, `double`
//! for xmm0–3. The proposal is review text; nothing applies it.

use permanent_beta_model::{ArgClass, BuildId, FunctionFeatures, HookSpec, PrototypeProposal};

/// A C prototype split into its parts: `int __fastcall F(Doc* doc, int n)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prototype {
    /// Everything before the name: return type and calling convention, e.g. `int __fastcall`.
    pub head: String,
    pub name: String,
    pub params: Vec<ProtoParam>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoParam {
    pub ty: String,
    pub name: Option<String>,
}

impl Prototype {
    /// Parses plain C prototypes. Returns `None` for anything it can't take apart safely (function-pointer
    /// parameters, variadics, missing parentheses), so no proposal is made from a misread prototype.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_end_matches(';').trim();
        let open = text.find('(')?;
        if !text.ends_with(')') {
            return None;
        }
        let inner = &text[open + 1..text.len() - 1];
        if inner.contains('(') || inner.contains(')') || inner.contains("...") {
            return None;
        }
        let before = text[..open].trim_end();
        let split = before.rfind(|c: char| !is_ident(c)).map_or(0, |i| i + 1);
        let (head, name) = (before[..split].trim(), &before[split..]);
        if head.is_empty() || name.is_empty() || name.starts_with(|c: char| c.is_ascii_digit()) {
            return None;
        }
        let inner = inner.trim();
        let params = if inner.is_empty() || inner == "void" {
            Vec::new()
        } else {
            inner
                .split(',')
                .map(|p| ProtoParam::parse(p.trim()))
                .collect::<Option<Vec<_>>>()?
        };
        Some(Self {
            head: head.to_owned(),
            name: name.to_owned(),
            params,
        })
    }

    pub fn returns_void(&self) -> bool {
        self.head
            .split_whitespace()
            .filter(|w| !w.starts_with("__"))
            .eq(["void"])
    }

    /// The return type without calling-convention keywords.
    fn return_type(&self) -> String {
        self.head
            .split_whitespace()
            .filter(|w| !w.starts_with("__"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn render(&self, name: &str, params: &[ProtoParam]) -> String {
        let list: Vec<String> = params.iter().map(ProtoParam::render).collect();
        let list = if list.is_empty() {
            "void".to_owned()
        } else {
            list.join(", ")
        };
        format!("{} {name}({list})", self.head)
    }
}

impl ProtoParam {
    fn parse(text: &str) -> Option<Self> {
        if text.is_empty() {
            return None;
        }
        // `const char* msg` → name `msg`; `int` alone, or `const char*`, has no name.
        let split = text.rfind(|c: char| !is_ident(c)).map_or(0, |i| i + 1);
        let (ty, name) = (text[..split].trim(), &text[split..]);
        Some(if ty.is_empty() || name.is_empty() || is_type_word(name) {
            Self {
                ty: text.to_owned(),
                name: None,
            }
        } else {
            Self {
                ty: ty.to_owned(),
                name: Some(name.to_owned()),
            }
        })
    }

    fn render(&self) -> String {
        match &self.name {
            Some(n) => format!("{} {n}", self.ty),
            None => self.ty.clone(),
        }
    }
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Words that end a type rather than name a parameter (`unsigned int`, `const char`).
fn is_type_word(w: &str) -> bool {
    matches!(
        w,
        "int"
            | "char"
            | "short"
            | "long"
            | "unsigned"
            | "signed"
            | "float"
            | "double"
            | "bool"
            | "void"
            | "const"
            | "volatile"
    )
}

/// Win64 passes the first four parameters in registers.
const REGISTER_SLOTS: usize = 4;

/// A proposal when `new` reads register arguments beyond the hook's declared prototype. `None` when the hook
/// has no parseable prototype, the prototype already covers what the new code reads, or the analyzer didn't
/// infer the argument registers.
pub fn propose(
    hook: &HookSpec,
    old: &FunctionFeatures,
    new: &FunctionFeatures,
    new_build: &BuildId,
) -> Option<PrototypeProposal> {
    let proto = Prototype::parse(hook.prototype.as_deref()?)?;
    let declared = proto.params.len();
    let read = new.inferred_args? as usize;
    if declared >= REGISTER_SLOTS || read <= declared {
        return None;
    }
    // The old code must not already read those slots: then the old prototype was simply incomplete, and the
    // detour, written against it, works as it did.
    if old.inferred_args.is_some_and(|o| o as usize >= read) {
        return None;
    }
    let mut params = proto.params.clone();
    let mut added = Vec::new();
    for slot in declared..read {
        let class = new
            .inferred_arg_classes
            .get(slot)
            .copied()
            .unwrap_or(ArgClass::Integer);
        let (ty, name) = match class {
            ArgClass::Vector => ("double", format!("arg{slot}")),
            ArgClass::Integer => ("intptr_t", format!("arg{slot}")),
            ArgClass::Unused => ("intptr_t", format!("unused{slot}")),
        };
        let p = ProtoParam {
            ty: ty.to_owned(),
            name: Some(name),
        };
        added.push((p.clone(), class));
        params.push(p);
    }
    let regs: Vec<String> = added
        .iter()
        .zip(declared..)
        .map(|((_, class), slot)| register_name(slot, *class))
        .collect();
    let basis = format!(
        "the new function reads {read} register arguments, the hook's prototype declares {declared}{}; the \
         added parameter{} ({}) {} guessed from the register class",
        old.inferred_args
            .map(|o| format!(" and the old function read {o}"))
            .unwrap_or_default(),
        if added.len() == 1 { "" } else { "s" },
        regs.join(", "),
        if added.len() == 1 {
            "type is"
        } else {
            "types are"
        },
    );
    Some(PrototypeProposal {
        candidate: new.rva,
        prototype: proto.render(&proto.name, &params),
        shim: shim(&proto, &params, declared, hook, new, new_build, &basis),
        basis,
    })
}

fn register_name(slot: usize, class: ArgClass) -> String {
    let int = ["rcx", "rdx", "r8", "r9"][slot];
    match class {
        ArgClass::Vector => format!("xmm{slot}"),
        ArgClass::Integer => int.to_owned(),
        ArgClass::Unused => format!("{int}, unread"),
    }
}

/// C++ shim text. Names follow the Detours convention the corpus hook DLL uses: `Hook_<name>` is the existing
/// detour and `Real_<name>` the pointer it calls the original function through.
fn shim(
    proto: &Prototype,
    params: &[ProtoParam],
    declared: usize,
    hook: &HookSpec,
    new: &FunctionFeatures,
    new_build: &BuildId,
    basis: &str,
) -> String {
    let n = &proto.name;
    let detour = hook.detour.clone().unwrap_or_else(|| format!("Hook_{n}"));
    let real = format!("Real_{n}");
    // Every parameter needs a name in the shim's own signatures.
    let named: Vec<ProtoParam> = params
        .iter()
        .enumerate()
        .map(|(i, p)| ProtoParam {
            ty: p.ty.clone(),
            name: Some(p.name.clone().unwrap_or_else(|| format!("p{i}"))),
        })
        .collect();
    let arg_names = |ps: &[ProtoParam]| {
        ps.iter()
            .map(|p| p.name.clone().unwrap_or_default())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (old_params, added) = named.split_at(declared);
    let ret = proto.return_type();
    let void = proto.returns_void();
    let fn_type = |params: &[ProtoParam]| {
        let list: Vec<String> = params.iter().map(ProtoParam::render).collect();
        format!(
            "{ret} (*)({})",
            if list.is_empty() {
                "void".to_owned()
            } else {
                list.join(", ")
            }
        )
    };

    let mut out = String::new();
    out.push_str(&format!(
        "// Proposed by pbeta for hook {} at {} (build {}). Review before use: {basis}.\n",
        hook.name,
        new.rva,
        new_build.0.get(..12).unwrap_or(&new_build.0)
    ));
    out.push_str(&format!(
        "using {n}_new_t = {};\nstatic {n}_new_t Real_{n}_new = nullptr;  // attach this one at {}\n",
        fn_type(&named),
        new.rva
    ));
    for p in added {
        out.push_str(&format!(
            "static thread_local {} {n}_{};\n",
            p.ty,
            p.name.as_deref().unwrap_or_default()
        ));
    }
    // The old detour calls the original through `Real_<name>` with the old parameters; this forwards the added
    // ones it doesn't know about.
    out.push_str(&format!(
        "// Set {real} = {n}_forward: the existing detour calls it as the original function.\n\
         static {} {n}_forward({}) {{\n    {}Real_{n}_new({});\n}}\n",
        ret,
        render_list(old_params),
        if void { "" } else { "return " },
        old_params
            .iter()
            .map(|p| p.name.clone().unwrap_or_default())
            .chain(
                added
                    .iter()
                    .map(|p| format!("{n}_{}", p.name.as_deref().unwrap_or_default()))
            )
            .collect::<Vec<_>>()
            .join(", "),
    ));
    out.push_str(&format!(
        "// The detour to attach: stash the added arguments (saved and restored for nested calls), then run the\n\
         // existing detour unchanged.\nstatic {} Shim_{n}({}) {{\n",
        ret,
        render_list(&named)
    ));
    for p in added {
        let a = p.name.as_deref().unwrap_or_default();
        out.push_str(&format!(
            "    {} saved_{a} = {n}_{a};\n    {n}_{a} = {a};\n",
            p.ty
        ));
    }
    let call = format!("{detour}({})", arg_names(old_params));
    if void {
        out.push_str(&format!("    {call};\n"));
    } else {
        out.push_str(&format!("    auto r = {call};\n"));
    }
    for p in added {
        let a = p.name.as_deref().unwrap_or_default();
        out.push_str(&format!("    {n}_{a} = saved_{a};\n"));
    }
    if !void {
        out.push_str("    return r;\n");
    }
    out.push_str("}\n");
    out
}

fn render_list(params: &[ProtoParam]) -> String {
    if params.is_empty() {
        return "void".to_owned();
    }
    params
        .iter()
        .map(ProtoParam::render)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use permanent_beta_model::{Criticality, Rva, TargetLocator};

    fn hook(prototype: &str) -> HookSpec {
        HookSpec {
            name: "log_event".into(),
            detour: Some("Hook_log_event".into()),
            criticality: Criticality::Normal,
            prototype: Some(prototype.into()),
            trial: false,
            target: TargetLocator {
                build: BuildId("v1".into()),
                rva: Some(Rva(0x10)),
                symbol: None,
                pattern: None,
            },
        }
    }

    fn func(rva: u64, classes: &[ArgClass]) -> FunctionFeatures {
        let mut f: FunctionFeatures =
            serde_json::from_value(serde_json::json!({ "rva": rva, "size": 32 })).unwrap();
        f.inferred_args = Some(classes.len() as u8);
        f.inferred_arg_classes = classes.to_vec();
        f
    }

    use ArgClass::{Integer as I, Vector as V};

    #[test]
    fn parses_prototypes() {
        let p =
            Prototype::parse("int __fastcall SaveDocument(Doc* doc, const wchar_t* path)").unwrap();
        assert_eq!(p.head, "int __fastcall");
        assert_eq!(p.name, "SaveDocument");
        assert_eq!(p.params[1].ty, "const wchar_t*");
        assert_eq!(p.params[1].name.as_deref(), Some("path"));
        assert!(!p.returns_void());

        let p = Prototype::parse("void f(void)").unwrap();
        assert!(p.params.is_empty() && p.returns_void());
        let p = Prototype::parse("unsigned checksum(const unsigned char*, unsigned int)").unwrap();
        assert_eq!(p.params[0].name, None);
        assert_eq!(p.params[1].name, None);

        // Too clever to take apart safely: no proposal is better than one from a misread prototype.
        assert_eq!(Prototype::parse("void f(void (*cb)(int), int n)"), None);
        assert_eq!(Prototype::parse("int printf(const char* fmt, ...)"), None);
        assert_eq!(Prototype::parse("not a prototype"), None);
    }

    #[test]
    fn an_added_register_parameter_is_proposed_with_a_shim() {
        let h = hook("void log_event(const char* msg, int code)");
        let p = propose(
            &h,
            &func(0x10, &[I, I]),
            &func(0x20, &[I, I, I]),
            &BuildId("v2".into()),
        )
        .unwrap();
        assert_eq!(p.candidate, Rva(0x20));
        assert_eq!(
            p.prototype,
            "void log_event(const char* msg, int code, intptr_t arg2)"
        );
        assert!(
            p.basis.contains("reads 3 register arguments"),
            "{}",
            p.basis
        );
        assert!(p.basis.contains("r8"), "{}", p.basis);
        // The shim keeps the old detour's view and forwards the added argument to the original.
        assert!(
            p.shim
                .contains("static void Shim_log_event(const char* msg, int code, intptr_t arg2)"),
            "{}",
            p.shim
        );
        assert!(p.shim.contains("Hook_log_event(msg, code);"), "{}", p.shim);
        assert!(
            p.shim
                .contains("Real_log_event_new(msg, code, log_event_arg2);"),
            "{}",
            p.shim
        );
        assert!(p.shim.contains("saved_arg2"), "{}", p.shim);
    }

    #[test]
    fn a_vector_register_becomes_a_double_and_results_are_returned() {
        let h = hook("int scale(int x)");
        let p = propose(
            &h,
            &func(0x10, &[I]),
            &func(0x20, &[I, V]),
            &BuildId("v2".into()),
        )
        .unwrap();
        assert_eq!(p.prototype, "int scale(int x, double arg1)");
        assert!(p.shim.contains("auto r = Hook_log_event(x);"), "{}", p.shim);
        assert!(p.shim.contains("return r;"), "{}", p.shim);
        assert!(
            p.shim.contains("return Real_scale_new(x, scale_arg1);"),
            "{}",
            p.shim
        );
    }

    #[test]
    fn no_proposal_without_an_added_parameter() {
        let h = hook("void log_event(const char* msg, int code)");
        let b = BuildId("v2".into());
        // Same register use.
        assert_eq!(
            propose(&h, &func(0x10, &[I, I]), &func(0x20, &[I, I]), &b),
            None
        );
        // Fewer registers read is not evidence of a removed parameter (the count is a lower bound).
        assert_eq!(
            propose(&h, &func(0x10, &[I, I]), &func(0x20, &[I]), &b),
            None
        );
        // The old code already read the third register: the prototype was incomplete, not the build changed.
        assert_eq!(
            propose(&h, &func(0x10, &[I, I, I]), &func(0x20, &[I, I, I]), &b),
            None
        );
        // No prototype to extend.
        let mut bare = h.clone();
        bare.prototype = None;
        assert_eq!(
            propose(&bare, &func(0x10, &[I, I]), &func(0x20, &[I, I, I]), &b),
            None
        );
        // Register use not inferred.
        let mut unknown = func(0x20, &[]);
        unknown.inferred_args = None;
        assert_eq!(propose(&h, &func(0x10, &[I, I]), &unknown, &b), None);
    }
}
