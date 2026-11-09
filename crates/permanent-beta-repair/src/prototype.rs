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

/// A proposal from both builds' PDB signatures (design §7.2): the new function's parameters are known exactly, so
/// any change is covered: added parameters (stack ones included), removed, reordered, retyped. Parameters
/// correspond by name: every parameter of both signatures must have one, unique, or there's no proposal (position
/// alone can't tell a reorder from a retype). The hook's prototype must have the old signature's parameter count
/// (it was written against the old function). The shim is the new detour: it takes the new parameters, calls the
/// existing detour with the old ones (by name; a removed one gets a value-initialized `{}`, a retyped one a cast),
/// and the existing detour's call to the original goes through `<name>_forward`, which passes the new parameters
/// (the added ones stashed by the shim). `None` when the signatures are missing or equal, or names don't line up.
pub fn propose_from_signatures(
    hook: &HookSpec,
    old: &FunctionFeatures,
    new: &FunctionFeatures,
    new_build: &BuildId,
) -> Option<PrototypeProposal> {
    let proto = Prototype::parse(hook.prototype.as_deref()?)?;
    let (os, ns) = (old.signature.as_ref()?, new.signature.as_ref()?);
    if os.params == ns.params && os.return_type == ns.return_type {
        return None;
    }
    if proto.params.len() != os.params.len() {
        return None;
    }
    let names = |ps: &[permanent_beta_model::Param]| -> Option<Vec<String>> {
        let v: Vec<String> = ps.iter().map(|p| p.name.clone()).collect::<Option<_>>()?;
        let mut sorted = v.clone();
        sorted.sort();
        sorted.dedup();
        (sorted.len() == v.len() && v.iter().all(|n| !n.is_empty())).then_some(v)
    };
    let (old_names, new_names) = (names(&os.params)?, names(&ns.params)?);
    let new_params: Vec<ProtoParam> = ns
        .params
        .iter()
        .map(|p| ProtoParam {
            ty: p.ty.clone(),
            name: p.name.clone(),
        })
        .collect();
    let head = match &ns.return_type {
        Some(r) if os.return_type.as_ref() != Some(r) => r.clone(),
        _ => proto.head.clone(),
    };
    let new_proto = Prototype {
        head,
        name: proto.name.clone(),
        params: new_params.clone(),
    };

    let mut changes = Vec::new();
    let added: Vec<&str> = new_names
        .iter()
        .filter(|n| !old_names.contains(n))
        .map(String::as_str)
        .collect();
    let removed: Vec<&str> = old_names
        .iter()
        .filter(|n| !new_names.contains(n))
        .map(String::as_str)
        .collect();
    let kept_old: Vec<&String> = old_names.iter().filter(|n| new_names.contains(n)).collect();
    let kept_new: Vec<&String> = new_names.iter().filter(|n| old_names.contains(n)).collect();
    let retyped: Vec<String> = os
        .params
        .iter()
        .filter_map(|o| {
            let n = ns.params.iter().find(|n| n.name == o.name)?;
            (n.ty != o.ty).then(|| {
                format!(
                    "{} {} -> {}",
                    o.name.as_deref().unwrap_or_default(),
                    o.ty,
                    n.ty
                )
            })
        })
        .collect();
    if !added.is_empty() {
        changes.push(format!("added {}", added.join(", ")));
    }
    if !removed.is_empty() {
        changes.push(format!(
            "removed {} (the shim passes the existing detour a value-initialized {{}}: check it doesn't rely on {})",
            removed.join(", "),
            if removed.len() == 1 { "it" } else { "them" }
        ));
    }
    if kept_old != kept_new {
        changes.push("reordered".into());
    }
    if !retyped.is_empty() {
        changes.push(format!(
            "retyped {} (cast in the shim: check the values survive)",
            retyped.join(", ")
        ));
    }
    let return_changed = matches!((&os.return_type, &ns.return_type), (Some(a), Some(b)) if a != b);
    if return_changed {
        changes.push(format!(
            "returns {} instead of {}",
            ns.return_type.as_deref().unwrap_or_default(),
            os.return_type.as_deref().unwrap_or_default()
        ));
    }
    if changes.is_empty() {
        return None;
    }
    let basis = format!(
        "from both builds' PDB signatures, parameters matched by name: {}",
        changes.join("; ")
    );
    let shim = if return_changed {
        format!(
            "// Proposed by pbeta for hook {} at {}: {basis}.\n// The return type changed: no shim; adapt the detour \
             by hand.\n",
            hook.name, new.rva
        )
    } else {
        signature_shim(&proto, &old_names, &new_proto, hook, new, new_build, &basis)
    };
    Some(PrototypeProposal {
        candidate: new.rva,
        prototype: new_proto.render(&new_proto.name, &new_proto.params),
        shim,
        basis,
    })
}

/// The shim for [`propose_from_signatures`]: the existing detour keeps the old prototype (`old`, whose parameter
/// `i` is the old signature's `old_names[i]`).
#[allow(clippy::too_many_arguments)]
fn signature_shim(
    old: &Prototype,
    old_names: &[String],
    new: &Prototype,
    hook: &HookSpec,
    at: &FunctionFeatures,
    new_build: &BuildId,
    basis: &str,
) -> String {
    let n = &old.name;
    let detour = hook.detour.clone().unwrap_or_else(|| format!("Hook_{n}"));
    let ret = old.return_type();
    let void = old.returns_void();
    let list = |ps: &[ProtoParam]| render_list(ps);
    let ty = |ps: &[ProtoParam]| {
        let l: Vec<String> = ps.iter().map(|p| p.ty.clone()).collect();
        if l.is_empty() {
            "void".to_owned()
        } else {
            l.join(", ")
        }
    };
    // The existing detour's own parameters, named after the old signature.
    let old_params: Vec<ProtoParam> = old
        .params
        .iter()
        .zip(old_names)
        .map(|(p, name)| ProtoParam {
            ty: p.ty.clone(),
            name: Some(name.clone()),
        })
        .collect();
    let added: Vec<&ProtoParam> = new
        .params
        .iter()
        .filter(|p| p.name.as_ref().is_some_and(|nm| !old_names.contains(nm)))
        .collect();
    let mut out = format!(
        "// Proposed by pbeta for hook {} at {} (build {}). Review before use: {basis}.\n",
        hook.name,
        at.rva,
        new_build.0.get(..12).unwrap_or(&new_build.0)
    );
    out.push_str(&format!(
        "using {n}_new_t = {ret} (*)({});\nstatic {n}_new_t Real_{n}_new = nullptr;  // attach this one at {}\n",
        ty(&new.params),
        at.rva
    ));
    for p in &added {
        out.push_str(&format!(
            "static thread_local {} {n}_{};\n",
            p.ty,
            p.name.as_deref().unwrap_or_default()
        ));
    }
    // The existing detour calls the original as Real_<name>(old parameters): forward them in the new order.
    let forward_args: Vec<String> = new
        .params
        .iter()
        .map(|p| {
            let name = p.name.clone().unwrap_or_default();
            match old_params
                .iter()
                .find(|o| o.name.as_deref() == Some(name.as_str()))
            {
                Some(o) if o.ty != p.ty => format!("({}){name}", p.ty),
                Some(_) => name,
                None => format!("{n}_{name}"),
            }
        })
        .collect();
    let dropped: String = old_params
        .iter()
        .filter_map(|o| o.name.as_deref())
        .filter(|name| !new.params.iter().any(|p| p.name.as_deref() == Some(*name)))
        .map(|name| format!("    (void){name};  // removed in the new build\n"))
        .collect();
    out.push_str(&format!(
        "// Set Real_{n} = {n}_forward: the existing detour calls it as the original function.\n\
         static {ret} {n}_forward({}) {{\n{dropped}    {}Real_{n}_new({});\n}}\n",
        list(&old_params),
        if void { "" } else { "return " },
        forward_args.join(", ")
    ));
    // The detour to attach: stash the added arguments, then run the existing detour with the old ones.
    out.push_str(&format!(
        "// The detour to attach: stash the added arguments (saved and restored for nested calls), then run the\n\
         // existing detour unchanged.\nstatic {ret} Shim_{n}({}) {{\n",
        list(&new.params)
    ));
    for p in &added {
        let a = p.name.as_deref().unwrap_or_default();
        out.push_str(&format!(
            "    {} saved_{a} = {n}_{a};\n    {n}_{a} = {a};\n",
            p.ty
        ));
    }
    let detour_args: Vec<String> = old_params
        .iter()
        .map(|o| {
            let name = o.name.clone().unwrap_or_default();
            match new
                .params
                .iter()
                .find(|p| p.name.as_deref() == Some(name.as_str()))
            {
                Some(p) if p.ty != o.ty => format!("({}){name}", o.ty),
                Some(_) => name,
                None => format!("{}{{}} /* {name}: removed in the new build */", o.ty),
            }
        })
        .collect();
    let call = format!("{detour}({})", detour_args.join(", "));
    if void {
        out.push_str(&format!("    {call};\n"));
    } else {
        out.push_str(&format!("    auto r = {call};\n"));
    }
    for p in &added {
        let a = p.name.as_deref().unwrap_or_default();
        out.push_str(&format!("    {n}_{a} = saved_{a};\n"));
    }
    if !void {
        out.push_str("    return r;\n");
    }
    out.push_str("}\n");
    out
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

    /// A function with a PDB signature: `(name, type)` parameters and a return type.
    fn signed(rva: u64, ret: &str, params: &[(&str, &str)]) -> FunctionFeatures {
        let mut f = func(rva, &[]);
        f.inferred_args = None;
        f.signature = Some(permanent_beta_model::FunctionSignature {
            calling_convention: None,
            return_type: Some(ret.into()),
            params: params
                .iter()
                .map(|(n, t)| permanent_beta_model::Param {
                    name: (!n.is_empty()).then(|| (*n).to_owned()),
                    ty: (*t).into(),
                })
                .collect(),
        });
        f
    }

    #[test]
    fn signatures_cover_added_stack_removed_and_reordered_parameters() {
        let h = hook("int place(int a, int b, int c, int d, int e)");
        let old = signed(
            0x10,
            "int",
            &[
                ("a", "int"),
                ("b", "int"),
                ("c", "int"),
                ("d", "int"),
                ("e", "int"),
            ],
        );
        // b removed; e moved to the front; f added (a stack parameter); d retyped.
        let new = signed(
            0x20,
            "int",
            &[
                ("e", "int"),
                ("a", "int"),
                ("c", "int"),
                ("d", "long long"),
                ("f", "int"),
                ("g", "int"),
            ],
        );
        let p = propose_from_signatures(&h, &old, &new, &BuildId("v2".into())).unwrap();
        assert_eq!(
            p.prototype,
            "int place(int e, int a, int c, long long d, int f, int g)"
        );
        for want in [
            "added f, g",
            "removed b",
            "reordered",
            "retyped d int -> long long",
        ] {
            assert!(p.basis.contains(want), "{want}: {}", p.basis);
        }
        // The new detour calls the existing one with the old parameters, by name: b is gone, d is cast back.
        assert!(
            p.shim.contains(
                "Hook_log_event(a, int{} /* b: removed in the new build */, c, (int)d, e)"
            ),
            "{}",
            p.shim
        );
        // And the existing detour's call to the original forwards in the new order, the added ones stashed.
        assert!(
            p.shim
                .contains("Real_place_new(e, a, c, (long long)d, place_f, place_g)"),
            "{}",
            p.shim
        );
        assert!(
            p.shim.contains("static thread_local int place_f;"),
            "{}",
            p.shim
        );
    }

    #[test]
    fn no_signature_proposal_without_names_or_a_matching_prototype() {
        let old = signed(0x10, "int", &[("a", "int"), ("b", "int")]);
        let new = signed(0x20, "int", &[("b", "int"), ("a", "int"), ("c", "int")]);
        let v2 = BuildId("v2".into());
        // Negative: an unnamed parameter (position can't tell a reorder from a retype).
        let unnamed = signed(0x20, "int", &[("", "int"), ("a", "int"), ("c", "int")]);
        assert_eq!(
            propose_from_signatures(&hook("int f(int a, int b)"), &old, &unnamed, &v2),
            None
        );
        // Negative: a name twice.
        let twice = signed(0x20, "int", &[("a", "int"), ("a", "int")]);
        assert_eq!(
            propose_from_signatures(&hook("int f(int a, int b)"), &old, &twice, &v2),
            None
        );
        // Negative: the hook's prototype doesn't have the old signature's parameter count.
        assert_eq!(
            propose_from_signatures(&hook("int f(int a)"), &old, &new, &v2),
            None
        );
        // Negative: nothing changed, or no signatures.
        assert_eq!(
            propose_from_signatures(&hook("int f(int a, int b)"), &old, &old, &v2),
            None
        );
        assert_eq!(
            propose_from_signatures(
                &hook("int f(int a, int b)"),
                &func(0x10, &[I, I]),
                &new,
                &v2
            ),
            None
        );
    }

    #[test]
    fn a_changed_return_type_gets_no_shim() {
        let old = signed(0x10, "int", &[("a", "int")]);
        let new = signed(0x20, "long long", &[("a", "int")]);
        let p = propose_from_signatures(&hook("int f(int a)"), &old, &new, &BuildId("v2".into()))
            .unwrap();
        assert_eq!(p.prototype, "long long f(int a)");
        assert!(p.shim.contains("no shim"), "{}", p.shim);
    }
}
