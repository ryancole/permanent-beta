//! Replay tests on a hand-built PE image: `.text` with one small function per case, `.rdata` with imports of
//! `kernel32.dll!Sleep` and `kernel32.dll!__acrt_iob_func` and a constant, `.data` with a global.

use super::*;
use permanent_beta_model::{
    BlobRef, BuildId, CaptureKind, EntryState, FieldLayout, GlobalRegion, GlobalVar, HarnessSpec,
    HookRecordSpec, Observed, Region, TestCase, Word, Xmm,
};

const BASE: u64 = 0x1_4000_0000;
const TEXT: u32 = 0x1000;
const RDATA: u32 = 0x2000;
const DATA: u32 = 0x3000;

// Functions in .text, by RVA.
const DOUBLE: u32 = 0x1000; // lea eax, [rcx+rcx]; ret
const READ_GLOBAL: u32 = 0x1010; // mov eax, [rip -> .data]; ret
const CALL_IMPORT: u32 = 0x1020; // call [rip -> IAT]; ret
const WRITE_FIELD: u32 = 0x1030; // mov [rcx+4], edx; ret
const READ_FAR: u32 = 0x1040; // mov eax, [rcx+0x100]; ret
const SPIN: u32 = 0x1050; // jmp $
const READ_AT_8: u32 = 0x1060; // mov eax, [rcx+8]; ret
const READ_CONST: u32 = 0x1070; // mov eax, [rip -> .rdata]; ret
const UPPER_GARBAGE: u32 = 0x1080; // mov rax, 0x1_0000_002a; ret
const TRIPLE: u32 = 0x1090; // lea eax, [rcx+rcx*2]; ret
const CALL_IOB: u32 = 0x10a0; // sub rsp, 28h; mov ecx, 1; call [rip -> IAT+8]; add rsp, 28h; ret
const WRITE_GLOBAL: u32 = 0x10c0; // mov [rip -> .data], ecx; ret

fn rel32(at: u32, len: u32, target: u32) -> [u8; 4] {
    (target.wrapping_sub(at + len) as i32).to_le_bytes()
}

fn text() -> Vec<u8> {
    let mut t = vec![0xcc; 0x200];
    let mut put = |rva: u32, bytes: &[u8]| {
        let o = (rva - TEXT) as usize;
        t[o..o + bytes.len()].copy_from_slice(bytes);
    };
    put(DOUBLE, &[0x8d, 0x04, 0x09, 0xc3]);
    let mut g = vec![0x8b, 0x05];
    g.extend(rel32(READ_GLOBAL, 6, DATA));
    g.push(0xc3);
    put(READ_GLOBAL, &g);
    let mut c = vec![0x48, 0x83, 0xec, 0x28, 0xff, 0x15]; // sub rsp, 28h; call [rip+x]
    c.extend(rel32(CALL_IMPORT + 4, 6, RDATA + 0x60));
    c.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]); // add rsp, 28h; ret
    put(CALL_IMPORT, &c);
    put(WRITE_FIELD, &[0x89, 0x51, 0x04, 0xc3]);
    put(READ_FAR, &[0x8b, 0x81, 0x00, 0x01, 0x00, 0x00, 0xc3]);
    put(SPIN, &[0xeb, 0xfe]);
    put(READ_AT_8, &[0x8b, 0x41, 0x08, 0xc3]);
    let mut k = vec![0x8b, 0x05];
    k.extend(rel32(READ_CONST, 6, RDATA + 0x100));
    k.push(0xc3);
    put(READ_CONST, &k);
    let mut u = vec![0x48, 0xb8];
    u.extend(0x1_0000_002au64.to_le_bytes());
    u.push(0xc3);
    put(UPPER_GARBAGE, &u);
    put(TRIPLE, &[0x8d, 0x04, 0x49, 0xc3]);
    let mut i = vec![
        0x48, 0x83, 0xec, 0x28, 0xb9, 0x01, 0x00, 0x00, 0x00, 0xff, 0x15,
    ];
    i.extend(rel32(CALL_IOB + 9, 6, RDATA + 0x68));
    i.extend([0x48, 0x83, 0xc4, 0x28, 0xc3]);
    put(CALL_IOB, &i);
    let mut w = vec![0x89, 0x0d];
    w.extend(rel32(WRITE_GLOBAL, 6, DATA));
    w.push(0xc3);
    put(WRITE_GLOBAL, &w);
    t
}

fn rdata() -> Vec<u8> {
    let mut r = vec![0u8; 0x200];
    let mut put = |off: usize, bytes: &[u8]| r[off..off + bytes.len()].copy_from_slice(bytes);
    // Import descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk; then a null one.
    put(0x00, &(RDATA + 0x40).to_le_bytes());
    put(0x0c, &(RDATA + 0x80).to_le_bytes());
    put(0x10, &(RDATA + 0x60).to_le_bytes());
    put(0x40, &u64::from(RDATA + 0xa0).to_le_bytes()); // INT
    put(0x48, &u64::from(RDATA + 0xc0).to_le_bytes());
    put(0x60, &u64::from(RDATA + 0xa0).to_le_bytes()); // IAT
    put(0x68, &u64::from(RDATA + 0xc0).to_le_bytes());
    put(0x80, b"kernel32.dll\0");
    put(0xa2, b"Sleep\0");
    put(0xc2, b"__acrt_iob_func\0");
    put(0x100, &1234u32.to_le_bytes());
    r
}

/// A minimal PE32+ image: headers, .text, .rdata (imports), .data.
fn pe() -> Vec<u8> {
    let mut f = vec![0u8; 0xa00];
    let mut put = |off: usize, bytes: &[u8]| f[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, b"MZ");
    put(0x3c, &0x80u32.to_le_bytes());
    put(0x80, b"PE\0\0");
    // COFF header: machine, sections, timestamp, symtab, symbols, optional header size, characteristics.
    put(0x84, &0x8664u16.to_le_bytes());
    put(0x86, &3u16.to_le_bytes());
    put(0x94, &0xf0u16.to_le_bytes());
    put(0x96, &0x22u16.to_le_bytes());
    let o = 0x98;
    put(o, &0x20bu16.to_le_bytes());
    put(o + 16, &TEXT.to_le_bytes()); // entry point
    put(o + 24, &BASE.to_le_bytes());
    put(o + 32, &0x1000u32.to_le_bytes()); // section alignment
    put(o + 36, &0x200u32.to_le_bytes()); // file alignment
    put(o + 40, &6u16.to_le_bytes()); // OS version
    put(o + 48, &6u16.to_le_bytes()); // subsystem version
    put(o + 56, &0x4000u32.to_le_bytes()); // size of image
    put(o + 60, &0x400u32.to_le_bytes()); // size of headers
    put(o + 68, &3u16.to_le_bytes()); // subsystem: console
    put(o + 108, &16u32.to_le_bytes()); // data directories
    put(o + 112 + 8, &RDATA.to_le_bytes()); // import directory
    put(o + 112 + 12, &40u32.to_le_bytes());
    let sections = [
        (b".text\0\0\0", TEXT, 0x400u32, 0x6000_0020u32),
        (b".rdata\0\0", RDATA, 0x600, 0x4000_0040),
        (b".data\0\0\0", DATA, 0x800, 0xc000_0040),
    ];
    for (i, (name, rva, raw, flags)) in sections.iter().enumerate() {
        let h = 0x188 + 40 * i;
        put(h, *name);
        put(h + 8, &0x200u32.to_le_bytes());
        put(h + 12, &rva.to_le_bytes());
        put(h + 16, &0x200u32.to_le_bytes());
        put(h + 20, &raw.to_le_bytes());
        put(h + 36, &flags.to_le_bytes());
    }
    put(0x400, &text());
    put(0x600, &rdata());
    put(0x800, &77u32.to_le_bytes());
    f
}

fn image() -> Image {
    Image::parse(&pe()).expect("test image parses")
}

fn spec(ret: ValueType) -> HarnessSpec {
    HarnessSpec {
        build: BuildId("old".into()),
        max_cases: 8,
        hooks: vec![HookRecordSpec {
            name: "f".into(),
            rva: Rva(0x1000),
            prototype: "int f(...)".into(),
            ret,
            stack_args: 0,
            args: Vec::new(),
            globals: Vec::new(),
        }],
        skipped: Vec::new(),
        layouts: vec![config_v1()],
    }
}

fn field(name: &str, offset: u64) -> FieldLayout {
    FieldLayout {
        name: name.into(),
        offset,
        size: 4,
        ty: "int".into(),
        bits: None,
    }
}

fn config(fields: Vec<FieldLayout>, size: u64) -> TypeLayout {
    TypeLayout {
        name: "Config".into(),
        size,
        union: false,
        fields,
    }
}

fn config_v1() -> TypeLayout {
    config(vec![field("a", 0), field("b", 4)], 8)
}

const STRUCT_AT: u64 = 0x5_0000_0010;

/// A case with rcx/rdx set, returning `rax`, and optionally one region at STRUCT_AT (passed in rcx).
fn case(rcx: u64, rdx: u64, rax: u64, region: Option<(&[u8], &[u8], Option<&str>)>) -> LoadedCase {
    let blob = BlobRef(format!("{:064x}", 0));
    let regions: Vec<LoadedRegion> = region
        .into_iter()
        .map(|(before, after, layout)| LoadedRegion {
            region: Region {
                arg: 0,
                address: Word(STRUCT_AT),
                size: before.len() as u64,
                kind: CaptureKind::Fixed,
                layout: layout.map(str::to_owned),
                before: blob.clone(),
                after: blob.clone(),
            },
            before: before.to_vec(),
            after: after.to_vec(),
        })
        .collect();
    LoadedCase {
        case: TestCase {
            test_id: "f-0001".into(),
            hook: "f".into(),
            build: BuildId("old".into()),
            rva: Rva(0x1000),
            recorder: "test".into(),
            abi: permanent_beta_model::ABI_WIN64.into(),
            image_base: Word(0x7ff6_0000_0000),
            entry: EntryState {
                rcx: Word(rcx),
                rdx: Word(rdx),
                r8: Word(0),
                r9: Word(0),
                xmm: [Xmm::default(); 4],
                stack: Vec::new(),
            },
            regions: regions.iter().map(|r| r.region.clone()).collect(),
            globals: Vec::new(),
            imports_recorded: false,
            imports: Vec::new(),
            observed: Observed {
                rax: Word(rax),
                xmm0: Xmm::default(),
            },
        },
        regions,
        globals: Vec::new(),
        imports: Vec::new(),
    }
}

/// `c` with the global `g_x` (4 bytes, at .data's start when recorded) before and after the call.
fn with_global(mut c: LoadedCase, before: u32, after: u32) -> LoadedCase {
    let blob = BlobRef(format!("{:064x}", 0));
    let g = GlobalRegion {
        name: "g_x".into(),
        rva: Rva(u64::from(DATA)),
        size: 4,
        before: blob.clone(),
        after: blob,
    };
    c.case.globals.push(g.clone());
    c.globals.push(LoadedGlobal {
        global: g,
        before: before.to_le_bytes().to_vec(),
        after: after.to_le_bytes().to_vec(),
    });
    c
}

/// The new build's `g_x`, `size` bytes at .data's start.
fn g_x(size: u64) -> Vec<GlobalVar> {
    vec![GlobalVar {
        name: "g_x".into(),
        rva: Rva(u64::from(DATA)),
        size,
        ty: "int".into(),
    }]
}

/// `c` with its import calls recorded: `__acrt_iob_func(index)` returning `file`, when `call` is given.
#[cfg(feature = "emulator")]
fn with_imports(mut c: LoadedCase, call: Option<(u64, u64)>) -> LoadedCase {
    c.case.imports_recorded = true;
    if let Some((index, file)) = call {
        let call = permanent_beta_model::ImportCall {
            import: "kernel32.dll!__acrt_iob_func".into(),
            entry: EntryState {
                rcx: Word(index),
                rdx: Word(0),
                r8: Word(0),
                r9: Word(0),
                xmm: [Xmm::default(); 4],
                stack: Vec::new(),
            },
            observed: Observed {
                rax: Word(file),
                xmm0: Xmm::default(),
            },
            memory: Vec::new(),
        };
        c.case.imports.push(call.clone());
        c.imports.push(LoadedImport {
            call,
            memory: Vec::new(),
        });
    }
    c
}

#[test]
fn the_test_image_parses() {
    let img = image();
    assert_eq!(img.preferred_base, BASE);
    assert_eq!(
        img.imports,
        vec![
            (RDATA + 0x60, "kernel32.dll!Sleep".to_owned()),
            (RDATA + 0x68, "kernel32.dll!__acrt_iob_func".to_owned())
        ]
    );
    let data = img.section_at(u64::from(DATA)).unwrap();
    assert!(data.writable && !data.executable);
    assert!(img.section_at(u64::from(TEXT)).unwrap().executable);
}

#[test]
fn nothing_to_compare_is_inconclusive() {
    // Negative: void, no memory.
    let o = replay(
        &image(),
        Rva(u64::from(DOUBLE)),
        &spec(ValueType::Void),
        &case(1, 0, 0, None),
        &NewBuild::default(),
    );
    assert!(matches!(o, CaseOutcome::Inconclusive { .. }), "{o:?}");
    // Negative: a return type that can't be compared.
    let o = replay(
        &image(),
        Rva(u64::from(DOUBLE)),
        &spec(ValueType::Unknown),
        &case(1, 0, 2, None),
        &NewBuild::default(),
    );
    assert!(matches!(o, CaseOutcome::Inconclusive { .. }), "{o:?}");
}

#[test]
fn a_struct_without_a_new_layout_is_inconclusive() {
    // Negative: the new build was analyzed without its PDB, so nobody knows whether Config changed.
    let r = [1, 0, 0, 0, 2, 0, 0, 0];
    let o = replay(
        &image(),
        Rva(u64::from(READ_AT_8)),
        &spec(ValueType::Int(4)),
        &case(STRUCT_AT, 0, 2, Some((&r, &r, Some("Config")))),
        &NewBuild::default(),
    );
    assert!(
        matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("--pdb")),
        "{o:?}"
    );
}

#[cfg(not(feature = "emulator"))]
#[test]
fn without_the_emulator_every_case_is_inconclusive() {
    let o = replay(
        &image(),
        Rva(u64::from(DOUBLE)),
        &spec(ValueType::Int(4)),
        &case(21, 0, 42, None),
        &NewBuild::default(),
    );
    assert!(
        matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("emulator")),
        "{o:?}"
    );
}

#[test]
fn a_global_the_new_build_lacks_is_inconclusive() {
    // Negative: no global of that name in the new build (analyzed without its PDB), or a different size.
    let c = with_global(case(0, 0, 5, None), 5, 5);
    let o = replay(
        &image(),
        Rva(u64::from(READ_GLOBAL)),
        &spec(ValueType::Int(4)),
        &c,
        &NewBuild::default(),
    );
    assert!(
        matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("no global g_x")),
        "{o:?}"
    );
    let o = replay(
        &image(),
        Rva(u64::from(READ_GLOBAL)),
        &spec(ValueType::Int(4)),
        &c,
        &NewBuild {
            layouts: &[],
            globals: &g_x(8),
        },
    );
    assert!(
        matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("8 bytes")),
        "{o:?}"
    );
}

#[cfg(feature = "emulator")]
mod emulated {
    use super::*;

    fn run(rva: u32, ret: ValueType, c: &LoadedCase, layouts: &[TypeLayout]) -> CaseOutcome {
        replay(
            &image(),
            Rva(u64::from(rva)),
            &spec(ret),
            c,
            &NewBuild {
                layouts,
                globals: &g_x(4),
            },
        )
    }

    fn inconclusive(o: &CaseOutcome, why: &str) {
        assert!(
            matches!(o, CaseOutcome::Inconclusive { reason } if reason.contains(why)),
            "expected inconclusive ({why}), got {o:?}"
        );
    }

    #[test]
    fn the_same_result_passes_and_a_different_one_fails() {
        let o = run(DOUBLE, ValueType::Int(4), &case(21, 0, 42, None), &[]);
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: another function (3x instead of 2x) on the same recorded call.
        let o = run(TRIPLE, ValueType::Int(4), &case(21, 0, 42, None), &[]);
        assert!(
            matches!(&o, CaseOutcome::Fail { detail } if detail.contains("0x3f")),
            "{o:?}"
        );
    }

    #[test]
    fn only_the_declared_width_of_the_return_value_is_compared() {
        // `int` lives in eax: the upper half of rax is whatever the code left there.
        let o = run(
            UPPER_GARBAGE,
            ValueType::Int(4),
            &case(0, 0, 0x2a, None),
            &[],
        );
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: declared 8 bytes wide, the upper half counts.
        let o = run(
            UPPER_GARBAGE,
            ValueType::Int(8),
            &case(0, 0, 0x2a, None),
            &[],
        );
        assert!(matches!(o, CaseOutcome::Fail { .. }), "{o:?}");
    }

    #[test]
    fn writes_to_recorded_memory_are_compared() {
        let before = [1, 0, 0, 0, 0, 0, 0, 0];
        let after = [1, 0, 0, 0, 9, 0, 0, 0];
        let o = run(
            WRITE_FIELD,
            ValueType::Void,
            &case(STRUCT_AT, 9, 0, Some((&before, &after, None))),
            &[],
        );
        assert!(
            matches!(&o, CaseOutcome::Pass { detail } if detail.contains("writes")),
            "{o:?}"
        );
        // Negative: the recording says 8 was written.
        let other = [1, 0, 0, 0, 8, 0, 0, 0];
        let o = run(
            WRITE_FIELD,
            ValueType::Void,
            &case(STRUCT_AT, 9, 0, Some((&before, &other, None))),
            &[],
        );
        assert!(
            matches!(&o, CaseOutcome::Fail { detail } if detail.contains("byte 0x4")),
            "{o:?}"
        );
    }

    #[test]
    fn reading_a_writable_global_is_inconclusive() {
        // Negative: .data holds 77, which would "pass" if the read were allowed.
        let o = run(READ_GLOBAL, ValueType::Int(4), &case(0, 0, 77, None), &[]);
        inconclusive(&o, "mutable global state");
        // Read-only data is part of the build and is fine.
        let o = run(READ_CONST, ValueType::Int(4), &case(0, 0, 1234, None), &[]);
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
    }

    #[test]
    fn calling_an_import_is_inconclusive() {
        let o = run(CALL_IMPORT, ValueType::Int(4), &case(0, 0, 0, None), &[]);
        inconclusive(&o, "kernel32.dll!Sleep");
        // Negative: recorded imports don't help an import replay has no model of.
        let c = with_imports(case(0, 0, 0, None), None);
        let o = run(CALL_IMPORT, ValueType::Int(4), &c, &[]);
        inconclusive(&o, "no model");
    }

    #[test]
    fn a_recorded_global_is_placed_and_compared() {
        // .data holds 77 in the file; the recording says the global was 5.
        let o = run(
            READ_GLOBAL,
            ValueType::Int(4),
            &with_global(case(0, 0, 5, None), 5, 5),
            &[],
        );
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: the file's value isn't what's read.
        let o = run(
            READ_GLOBAL,
            ValueType::Int(4),
            &with_global(case(0, 0, 77, None), 5, 5),
            &[],
        );
        assert!(matches!(o, CaseOutcome::Fail { .. }), "{o:?}");
        // Writes to it are compared.
        let o = run(
            WRITE_GLOBAL,
            ValueType::Void,
            &with_global(case(9, 0, 0, None), 5, 9),
            &[],
        );
        assert!(
            matches!(&o, CaseOutcome::Pass { detail } if detail.contains("global g_x writes")),
            "{o:?}"
        );
        // Negative: the recording says 8 was written.
        let o = run(
            WRITE_GLOBAL,
            ValueType::Void,
            &with_global(case(9, 0, 0, None), 5, 8),
            &[],
        );
        assert!(
            matches!(&o, CaseOutcome::Fail { detail } if detail.contains("global g_x byte 0x0")),
            "{o:?}"
        );
    }

    #[test]
    fn a_recorded_import_call_is_answered_from_the_recording() {
        let file = 0x7ff0_0000_0010;
        let o = run(
            CALL_IOB,
            ValueType::Int(8),
            &with_imports(case(0, 0, file, None), Some((1, file))),
            &[],
        );
        assert!(
            matches!(&o, CaseOutcome::Pass { detail } if detail.contains("1 import call")),
            "{o:?}"
        );
        // Negative: the recorded call asked for another stream (here or in a callee whose behaviour changed:
        // never a pass, and not a fail of this function either).
        let o = run(
            CALL_IOB,
            ValueType::Int(8),
            &with_imports(case(0, 0, file, None), Some((2, file))),
            &[],
        );
        inconclusive(&o, "index 0x1, recorded 0x2");
        // Negative: imports recorded, but this call wasn't (the old function made none).
        let o = run(
            CALL_IOB,
            ValueType::Int(8),
            &with_imports(case(0, 0, file, None), None),
            &[],
        );
        inconclusive(&o, "after the 0 import call");
        // Negative: the old function made a call the candidate doesn't.
        let o = run(
            DOUBLE,
            ValueType::Int(4),
            &with_imports(case(21, 0, 42, None), Some((1, file))),
            &[],
        );
        inconclusive(&o, "made 0 of the 1");
        // Negative: without recorded imports, the call stops the run.
        let o = run(CALL_IOB, ValueType::Int(8), &case(0, 0, file, None), &[]);
        inconclusive(&o, "calls the import kernel32.dll!__acrt_iob_func");
    }

    #[test]
    fn reading_memory_nobody_recorded_is_inconclusive() {
        let r = [0u8; 8];
        let o = run(
            READ_FAR,
            ValueType::Int(4),
            &case(STRUCT_AT, 0, 0, Some((&r, &r, None))),
            &[],
        );
        inconclusive(&o, "didn't capture");
        // Negative: a pointer argument with no recorded memory at all.
        let o = run(
            READ_AT_8,
            ValueType::Int(4),
            &case(0x9_0000_0000, 0, 0, None),
            &[],
        );
        inconclusive(&o, "didn't capture");
    }

    #[test]
    fn a_function_that_never_returns_is_inconclusive() {
        let o = run(SPIN, ValueType::Int(4), &case(0, 0, 0, None), &[]);
        inconclusive(&o, "didn't return");
    }

    #[test]
    fn a_changed_layout_is_translated_by_field_name() {
        // Old Config {a@0, b@4}; the new build moved b to 8. The new code reads b at 8.
        let new = config(vec![field("a", 0), field("b", 8)], 12);
        let r = [1, 0, 0, 0, 7, 0, 0, 0];
        let c = case(STRUCT_AT, 0, 7, Some((&r, &r, Some("Config"))));
        let o = run(READ_AT_8, ValueType::Int(4), &c, &[new]);
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: replayed untranslated (same layout claimed), the new code would read past the struct.
        let o = run(READ_AT_8, ValueType::Int(4), &c, &[config_v1()]);
        assert!(!matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: a new field has no recorded value.
        let added = config(vec![field("a", 0), field("inserted", 4), field("b", 8)], 12);
        let o = run(READ_AT_8, ValueType::Int(4), &c, &[added]);
        inconclusive(&o, "inserted is new");
    }
}
