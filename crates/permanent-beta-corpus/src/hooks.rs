//! Answer key for the M4 hook-repair loop (corpus/hooks): write the v1 manifest from symbols, and check repaired
//! manifests against the linker maps. Scoring only: the pipeline never sees symbols or maps.

use crate::map::MapFile;
use permanent_beta_model::{BuildId, HookManifest, Rva};
use serde::{Deserialize, Serialize};

/// The v1 manifest from a template whose locators name symbols: each symbol is resolved to its RVA through
/// `map`, the locator is bound to `build`, and the symbol is dropped (repair sees RVAs only).
pub fn manifest_from_template(
    template: &HookManifest,
    map: &MapFile,
    build: &BuildId,
) -> Result<HookManifest, String> {
    let mut out = template.clone();
    for hook in &mut out.hooks {
        let symbol = hook
            .target
            .symbol
            .take()
            .ok_or_else(|| format!("hook {}: the template needs target.symbol", hook.name))?;
        let found: Vec<Rva> = map
            .symbols
            .iter()
            .filter(|s| s.is_function && s.name == symbol)
            .map(|s| s.rva)
            .collect();
        let [rva] = found[..] else {
            return Err(format!(
                "hook {}: symbol {symbol} found {} times in the map",
                hook.name,
                found.len()
            ));
        };
        hook.target.rva = Some(rva);
        hook.target.build = build.clone();
    }
    Ok(out)
}

/// One hook of a repaired manifest, judged against the answer key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "truth", rename_all = "snake_case")]
pub enum HookTruth {
    /// Re-bound to the new build at the function with the same symbol.
    Correct { symbol: String, old: Rva, new: Rva },
    /// Re-bound to the new build at the wrong address (or from a locator that wasn't valid for the old build).
    Wrong {
        detail: String,
        old: Option<Rva>,
        new: Rva,
    },
    /// Still bound to an older build: repair didn't resolve it.
    Held,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookCheck {
    pub hook: String,
    #[serde(flatten)]
    pub truth: HookTruth,
}

fn symbols_at(map: &MapFile, rva: Rva) -> Vec<&str> {
    map.symbols
        .iter()
        .filter(|s| s.is_function && s.rva == rva)
        .map(|s| s.name.as_str())
        .collect()
}

/// Judge every hook of `new_manifest` (repaired from `old_manifest`) against the two builds' maps.
pub fn check_hooks(
    old_manifest: &HookManifest,
    new_manifest: &HookManifest,
    old_map: &MapFile,
    new_map: &MapFile,
    old_build: &BuildId,
    new_build: &BuildId,
) -> Vec<HookCheck> {
    new_manifest
        .hooks
        .iter()
        .map(|h| {
            let truth = judge(old_manifest, h, old_map, new_map, old_build, new_build);
            HookCheck {
                hook: h.name.clone(),
                truth,
            }
        })
        .collect()
}

fn judge(
    old_manifest: &HookManifest,
    h: &permanent_beta_model::HookSpec,
    old_map: &MapFile,
    new_map: &MapFile,
    old_build: &BuildId,
    new_build: &BuildId,
) -> HookTruth {
    if h.target.build != *new_build {
        return HookTruth::Held;
    }
    let Some(new) = h.target.rva else {
        return HookTruth::Wrong {
            detail: "bound to the new build without an RVA".into(),
            old: None,
            new: Rva(0),
        };
    };
    let wrong = |detail: String, old| HookTruth::Wrong { detail, old, new };
    let Some(before) = old_manifest.hooks.iter().find(|o| o.name == h.name) else {
        return wrong("not in the old manifest".into(), None);
    };
    let old = before.target.rva;
    if before.target.build != *old_build {
        return wrong(
            "resolved from a locator that was bound to another build".into(),
            old,
        );
    }
    let Some(old_rva) = old else {
        return wrong("the old locator has no RVA".into(), None);
    };
    let old_syms = symbols_at(old_map, old_rva);
    let new_syms = symbols_at(new_map, new);
    match old_syms.iter().find(|s| new_syms.contains(s)) {
        Some(s) => HookTruth::Correct {
            symbol: (*s).to_owned(),
            old: old_rva,
            new,
        },
        None => wrong(
            format!(
                "old {old_rva} is {}, new {new} is {}",
                describe(&old_syms),
                describe(&new_syms)
            ),
            old,
        ),
    }
}

fn describe(syms: &[&str]) -> String {
    if syms.is_empty() {
        "no function".into()
    } else {
        syms.join("/")
    }
}

/// Swap two hooks' RVAs (a deliberately wrong relocation, for negative controls).
pub fn swap(manifest: &HookManifest, a: &str, b: &str) -> Result<HookManifest, String> {
    let mut out = manifest.clone();
    let find = |m: &HookManifest, n: &str| {
        m.hooks
            .iter()
            .position(|h| h.name == n)
            .ok_or_else(|| format!("no hook {n}"))
    };
    let (ia, ib) = (find(&out, a)?, find(&out, b)?);
    let (ra, rb) = (out.hooks[ia].target.rva, out.hooks[ib].target.rva);
    out.hooks[ia].target.rva = rb;
    out.hooks[ib].target.rva = ra;
    Ok(out)
}

/// corpus/hooks/expected.toml: what each repair step must achieve.
#[derive(Debug, Clone, Deserialize)]
pub struct HookExpected {
    #[serde(rename = "step", default)]
    pub steps: Vec<StepExpected>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StepExpected {
    /// e.g. `v1-v2`.
    pub name: String,
    /// The flag set this applies to.
    pub flags: String,
    /// At least this many hooks re-bound to the new build (all of them correctly).
    pub min_resolved: usize,
    /// Hooks that must stay unresolved (sent to review), e.g. one whose signature changed.
    #[serde(default)]
    pub held: Vec<String>,
}

impl HookExpected {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    pub fn step(&self, name: &str, flags: &str) -> Option<&StepExpected> {
        self.steps
            .iter()
            .find(|s| s.name == name && s.flags == flags)
    }
}

/// Gate failures for one step; empty means it passed. Wrong relocations always fail, with or without
/// expectations.
pub fn gate(checks: &[HookCheck], expected: Option<&StepExpected>) -> Vec<String> {
    let mut failures: Vec<String> = checks
        .iter()
        .filter_map(|c| match &c.truth {
            HookTruth::Wrong { detail, .. } => {
                Some(format!("{}: wrong relocation ({detail})", c.hook))
            }
            _ => None,
        })
        .collect();
    let Some(e) = expected else {
        return failures;
    };
    let resolved = checks
        .iter()
        .filter(|c| matches!(c.truth, HookTruth::Correct { .. }))
        .count();
    if resolved < e.min_resolved {
        failures.push(format!(
            "{resolved} hooks resolved, below the baseline of {}",
            e.min_resolved
        ));
    }
    for name in &e.held {
        match checks.iter().find(|c| &c.hook == name) {
            Some(c) if c.truth == HookTruth::Held => {}
            Some(_) => failures.push(format!("{name}: must stay in review, but was resolved")),
            None => failures.push(format!("{name}: not in the manifest")),
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::MapSymbol;
    use permanent_beta_model::{Criticality, HookSpec, TargetLocator};

    fn map(syms: &[(&str, u64)]) -> MapFile {
        MapFile {
            preferred_base: 0x1_4000_0000,
            symbols: syms
                .iter()
                .map(|(n, r)| MapSymbol {
                    name: (*n).into(),
                    rva: Rva(*r),
                    is_function: true,
                    is_static: false,
                    object: "app.obj".into(),
                })
                .collect(),
        }
    }

    fn manifest(build: &str, hooks: &[(&str, u64)]) -> HookManifest {
        HookManifest {
            hooks: hooks
                .iter()
                .map(|(n, r)| HookSpec {
                    name: (*n).into(),
                    detour: None,
                    criticality: Criticality::Normal,
                    prototype: None,
                    target: TargetLocator {
                        build: BuildId(build.into()),
                        rva: Some(Rva(*r)),
                        symbol: None,
                        pattern: None,
                    },
                })
                .collect(),
        }
    }

    fn ids() -> (BuildId, BuildId) {
        (BuildId("v1".into()), BuildId("v2".into()))
    }

    #[test]
    fn template_symbols_resolve_through_the_map() {
        let mut t = manifest("v1", &[("price", 0)]);
        t.hooks[0].target.rva = None;
        t.hooks[0].target.symbol = Some("price_lookup".into());
        let m = manifest_from_template(
            &t,
            &map(&[("price_lookup", 0x1250)]),
            &BuildId("abc".into()),
        )
        .unwrap();
        assert_eq!(m.hooks[0].target.rva, Some(Rva(0x1250)));
        assert_eq!(m.hooks[0].target.build, BuildId("abc".into()));
        assert_eq!(m.hooks[0].target.symbol, None);

        t.hooks[0].target.symbol = Some("missing".into());
        assert!(manifest_from_template(&t, &map(&[]), &BuildId("abc".into())).is_err());
    }

    #[test]
    fn correct_wrong_and_held_relocations() {
        let (v1, v2) = ids();
        let old_map = map(&[("price", 0x100), ("stock", 0x200), ("log", 0x300)]);
        let new_map = map(&[("price", 0x180), ("stock", 0x280), ("log", 0x380)]);
        let old = manifest("v1", &[("price", 0x100), ("stock", 0x200), ("log", 0x300)]);
        let mut new = manifest("v2", &[("price", 0x180), ("stock", 0x180), ("log", 0x300)]);
        new.hooks[2].target.build = v1.clone(); // held

        let checks = check_hooks(&old, &new, &old_map, &new_map, &v1, &v2);
        assert!(matches!(checks[0].truth, HookTruth::Correct { .. }));
        assert!(
            matches!(checks[1].truth, HookTruth::Wrong { .. }),
            "{:?}",
            checks[1]
        );
        assert_eq!(checks[2].truth, HookTruth::Held);
        assert_eq!(gate(&checks, None).len(), 1);
    }

    #[test]
    fn swapped_hooks_are_both_wrong() {
        let (v1, v2) = ids();
        let old_map = map(&[("price", 0x100), ("stock", 0x200)]);
        let new_map = map(&[("price", 0x180), ("stock", 0x280)]);
        let old = manifest("v1", &[("price", 0x100), ("stock", 0x200)]);
        let new = swap(
            &manifest("v2", &[("price", 0x180), ("stock", 0x280)]),
            "price",
            "stock",
        )
        .unwrap();
        let checks = check_hooks(&old, &new, &old_map, &new_map, &v1, &v2);
        assert_eq!(gate(&checks, None).len(), 2, "{checks:?}");
    }

    #[test]
    fn resolving_a_stale_locator_is_wrong_even_at_the_right_address() {
        // The old locator was bound to v0, so its RVA said nothing about v1; resolving it is a lucky guess.
        let (v1, v2) = ids();
        let old_map = map(&[("price", 0x100)]);
        let new_map = map(&[("price", 0x180)]);
        let old = manifest("v0", &[("price", 0x100)]);
        let new = manifest("v2", &[("price", 0x180)]);
        let checks = check_hooks(&old, &new, &old_map, &new_map, &v1, &v2);
        assert!(matches!(checks[0].truth, HookTruth::Wrong { .. }));
    }

    #[test]
    fn the_gate_enforces_baselines_and_held_hooks() {
        let (v1, v2) = ids();
        let old_map = map(&[("price", 0x100), ("log", 0x300)]);
        let new_map = map(&[("price", 0x180), ("log", 0x380)]);
        let old = manifest("v1", &[("price", 0x100), ("log", 0x300)]);
        let new = manifest("v2", &[("price", 0x180), ("log", 0x380)]);
        let checks = check_hooks(&old, &new, &old_map, &new_map, &v1, &v2);
        let step = StepExpected {
            name: "v1-v2".into(),
            flags: "o2".into(),
            min_resolved: 3,
            held: vec!["log".into()],
        };
        let failures = gate(&checks, Some(&step));
        assert_eq!(failures.len(), 2, "{failures:?}");
    }
}
