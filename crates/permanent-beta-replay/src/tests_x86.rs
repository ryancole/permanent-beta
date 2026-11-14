//! Replay tests for x86 (Win32) on a hand-built PE32 image based at 0x400000: `.text` with one small function per
//! case, `.rdata` importing `vcruntime140.dll!memcpy`, `.data` empty.

use super::*;
use permanent_beta_model::{
    Abi, BuildId, Convention, EntryState, HarnessSpec, HookRecordSpec, Observed, TestCase, Word,
    Xmm,
};

const BASE: u32 = 0x40_0000;
const RDATA: u32 = 0x2000;
const IAT: u32 = RDATA + 0x50;

// Functions in .text, by RVA.
/// `int __cdecl add(int a, int b)`: mov eax, [esp+4]; add eax, [esp+8]; ret
const ADD_CDECL: u32 = 0x1000;
/// `int __stdcall add(int a, int b)`: the same, then `ret 8`.
const ADD_STDCALL: u32 = 0x1010;
/// `int __thiscall S::get(int i)`: mov eax, [ecx+4]; add eax, [esp+4]; ret 4
const GET_THIS: u32 = 0x1020;
/// `float twice(float x)`: fld dword [esp+4]; fadd st0, st0; ret
const TWICE_FLOAT: u32 = 0x1030;
/// `unsigned __int64 wide(unsigned lo, unsigned hi)`: mov eax, [esp+4]; mov edx, [esp+8]; ret
const WIDE: u32 = 0x1040;
/// `void copy8(void* dst, const void* src)`: memcpy(dst, src, 8) through the IAT; ret
const COPY8: u32 = 0x1050;

#[cfg(feature = "emulator")]
const STRUCT_AT: u32 = 0x0050_0010;
#[cfg(feature = "emulator")]
const SRC_AT: u32 = 0x0050_1000;

fn text() -> Vec<u8> {
    let mut t = vec![0xcc; 0x200];
    let mut put = |rva: u32, bytes: &[u8]| {
        let o = (rva - 0x1000) as usize;
        t[o..o + bytes.len()].copy_from_slice(bytes);
    };
    let add = [0x8b, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08];
    put(ADD_CDECL, &[&add[..], &[0xc3]].concat());
    put(ADD_STDCALL, &[&add[..], &[0xc2, 0x08, 0x00]].concat());
    put(
        GET_THIS,
        &[0x8b, 0x41, 0x04, 0x03, 0x44, 0x24, 0x04, 0xc2, 0x04, 0x00],
    );
    put(TWICE_FLOAT, &[0xd9, 0x44, 0x24, 0x04, 0xd8, 0xc0, 0xc3]);
    put(
        WIDE,
        &[0x8b, 0x44, 0x24, 0x04, 0x8b, 0x54, 0x24, 0x08, 0xc3],
    );
    // push 8; push [esp+0Ch] (src); push [esp+0Ch] (dst); call [memcpy]; add esp, 0Ch; ret
    let mut c = vec![
        0x6a, 0x08, 0xff, 0x74, 0x24, 0x0c, 0xff, 0x74, 0x24, 0x0c, 0xff, 0x15,
    ];
    c.extend((BASE + IAT).to_le_bytes());
    c.extend([0x83, 0xc4, 0x0c, 0xc3]);
    put(COPY8, &c);
    t
}

fn rdata() -> Vec<u8> {
    let mut r = vec![0u8; 0x200];
    let mut put = |off: usize, bytes: &[u8]| r[off..off + bytes.len()].copy_from_slice(bytes);
    // Import descriptor: lookup table 0x2040, name 0x2100, IAT 0x2050; then a null one.
    put(0x00, &(RDATA + 0x40).to_le_bytes());
    put(0x0c, &(RDATA + 0x100).to_le_bytes());
    put(0x10, &IAT.to_le_bytes());
    put(0x100, b"vcruntime140.dll\0");
    put(0x40, &(RDATA + 0x60).to_le_bytes());
    put(0x50, &(RDATA + 0x60).to_le_bytes());
    put(0x62, b"memcpy\0");
    r
}

/// A minimal PE32 image: headers, .text, .rdata (imports), .data.
fn pe32() -> Vec<u8> {
    let mut f = vec![0u8; 0xa00];
    let mut put = |off: usize, bytes: &[u8]| f[off..off + bytes.len()].copy_from_slice(bytes);
    put(0, b"MZ");
    put(0x3c, &0x80u32.to_le_bytes());
    put(0x80, b"PE\0\0");
    put(0x84, &0x14cu16.to_le_bytes()); // i386
    put(0x86, &3u16.to_le_bytes());
    put(0x94, &0xe0u16.to_le_bytes());
    put(0x96, &0x102u16.to_le_bytes());
    let o = 0x98;
    put(o, &0x10bu16.to_le_bytes()); // PE32
    put(o + 16, &ADD_CDECL.to_le_bytes());
    put(o + 28, &BASE.to_le_bytes());
    put(o + 32, &0x1000u32.to_le_bytes());
    put(o + 36, &0x200u32.to_le_bytes());
    put(o + 40, &6u16.to_le_bytes());
    put(o + 48, &6u16.to_le_bytes());
    put(o + 56, &0x4000u32.to_le_bytes());
    put(o + 60, &0x400u32.to_le_bytes());
    put(o + 68, &3u16.to_le_bytes());
    put(o + 92, &16u32.to_le_bytes());
    put(o + 96 + 8, &RDATA.to_le_bytes()); // import directory
    put(o + 96 + 12, &40u32.to_le_bytes());
    let sections = [
        (b".text\0\0\0", 0x1000u32, 0x400u32, 0x6000_0020u32),
        (b".rdata\0\0", RDATA, 0x600, 0x4000_0040),
        (b".data\0\0\0", 0x3000, 0x800, 0xc000_0040),
    ];
    for (i, (name, rva, raw, flags)) in sections.iter().enumerate() {
        let h = 0x178 + 40 * i;
        put(h, *name);
        put(h + 8, &0x200u32.to_le_bytes());
        put(h + 12, &rva.to_le_bytes());
        put(h + 16, &0x200u32.to_le_bytes());
        put(h + 20, &raw.to_le_bytes());
        put(h + 36, &flags.to_le_bytes());
    }
    put(0x400, &text());
    put(0x600, &rdata());
    f
}

fn image() -> Image {
    Image::parse(&pe32()).expect("the PE32 test image parses")
}

fn spec(ret: ValueType, stack_args: u32, convention: Convention) -> HarnessSpec {
    HarnessSpec {
        build: BuildId("old".into()),
        abi: Abi::Win32,
        max_cases: 8,
        import_memory: true,
        pointer_depth: 0,
        pointers: Vec::new(),
        hooks: vec![HookRecordSpec {
            name: "f".into(),
            rva: Rva(0x1000),
            prototype: "int f(...)".into(),
            ret,
            stack_args,
            convention: Some(convention),
            args: Vec::new(),
            globals: Vec::new(),
        }],
        skipped: Vec::new(),
        layouts: Vec::new(),
    }
}

/// A Win32 case: ecx, the stack words, and what it returned (edx:eax; st(0) as `xmm0`'s bytes).
fn case(ecx: u32, stack: &[u32], rax: u64, xmm0: &[u8]) -> LoadedCase {
    let mut x = [0u8; 16];
    x[..xmm0.len()].copy_from_slice(xmm0);
    LoadedCase {
        case: TestCase {
            test_id: "f-0001".into(),
            hook: "f".into(),
            build: BuildId("old".into()),
            rva: Rva(0x1000),
            recorder: "test".into(),
            abi: permanent_beta_model::ABI_WIN32.into(),
            image_base: Word(u64::from(BASE)),
            image_size: Some(Word(0x4000)),
            entry: EntryState {
                rcx: Word(u64::from(ecx)),
                rdx: Word(0),
                r8: Word(0),
                r9: Word(0),
                xmm: [Xmm::default(); 4],
                stack: stack.iter().map(|&w| Word(u64::from(w))).collect(),
            },
            regions: Vec::new(),
            globals: Vec::new(),
            imports_recorded: false,
            imports: Vec::new(),
            observed: Observed {
                rax: Word(rax),
                xmm0: Xmm(x),
            },
        },
        regions: Vec::new(),
        globals: Vec::new(),
        imports: Vec::new(),
    }
}

#[cfg(feature = "emulator")]
/// `c` with a recorded region at `address` (argument `arg`).
fn with_region(
    mut c: LoadedCase,
    arg: u32,
    address: u32,
    before: &[u8],
    after: &[u8],
) -> LoadedCase {
    let blob = permanent_beta_model::BlobRef(format!("{:064x}", 0));
    let region = permanent_beta_model::Region {
        arg,
        address: Word(u64::from(address)),
        size: before.len() as u64,
        kind: permanent_beta_model::CaptureKind::Fixed,
        layout: None,
        before: blob.clone(),
        after: blob,
    };
    c.case.regions.push(region.clone());
    c.regions.push(LoadedRegion {
        region,
        before: before.to_vec(),
        after: after.to_vec(),
    });
    c
}

fn run(rva: u32, spec: &HarnessSpec, c: &LoadedCase) -> CaseOutcome {
    replay(&image(), Rva(u64::from(rva)), spec, c, &NewBuild::default())
}

fn int4() -> ValueType {
    ValueType::Int(4)
}

#[test]
fn the_pe32_test_image_parses() {
    let img = image();
    assert!(img.x86);
    assert_eq!(img.preferred_base, u64::from(BASE));
    assert_eq!(img.pointer_size(), 4);
    assert_eq!(
        img.imports,
        vec![(IAT, "vcruntime140.dll!memcpy".to_owned())]
    );
}

#[test]
fn an_x64_recording_is_not_replayed_on_an_x86_image() {
    // Negative: the slots mean something else.
    let mut c = case(0, &[2, 3], 5, &[]);
    c.case.abi = permanent_beta_model::ABI_WIN64.into();
    let o = run(ADD_CDECL, &spec(int4(), 2, Convention::Cdecl), &c);
    assert!(
        matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("ABI")),
        "{o:?}"
    );
}

#[cfg(feature = "emulator")]
mod emulated {
    use super::*;

    #[test]
    fn cdecl_stack_arguments_are_replayed() {
        let s = spec(int4(), 2, Convention::Cdecl);
        let o = run(ADD_CDECL, &s, &case(0, &[2, 3], 5, &[]));
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: another result is a fail.
        let o = run(ADD_CDECL, &s, &case(0, &[2, 3], 6, &[]));
        assert!(matches!(o, CaseOutcome::Fail { .. }), "{o:?}");
    }

    #[test]
    fn a_callee_that_pops_its_arguments_returns_balanced() {
        let o = run(
            ADD_STDCALL,
            &spec(int4(), 2, Convention::Stdcall),
            &case(0, &[2, 3], 5, &[]),
        );
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: a __cdecl hook replayed on a function that pops 8 bytes leaves the stack unbalanced, and the
        // other way round.
        let o = run(
            ADD_STDCALL,
            &spec(int4(), 2, Convention::Cdecl),
            &case(0, &[2, 3], 5, &[]),
        );
        assert!(
            matches!(&o, CaseOutcome::Inconclusive { reason } if reason.contains("unbalanced")),
            "{o:?}"
        );
        let o = run(
            ADD_CDECL,
            &spec(int4(), 2, Convention::Stdcall),
            &case(0, &[2, 3], 5, &[]),
        );
        assert!(matches!(o, CaseOutcome::Inconclusive { .. }), "{o:?}");
    }

    #[test]
    fn thiscall_reads_this_from_ecx() {
        let s = spec(int4(), 1, Convention::Thiscall);
        let c = with_region(
            case(STRUCT_AT, &[10], 17, &[]),
            0,
            STRUCT_AT,
            &[0, 0, 0, 0, 7, 0, 0, 0],
            &[0, 0, 0, 0, 7, 0, 0, 0],
        );
        let o = run(GET_THIS, &s, &c);
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: the field differs in the recording.
        let c = with_region(
            case(STRUCT_AT, &[10], 17, &[]),
            0,
            STRUCT_AT,
            &[0, 0, 0, 0, 8, 0, 0, 0],
            &[0, 0, 0, 0, 8, 0, 0, 0],
        );
        assert!(matches!(run(GET_THIS, &s, &c), CaseOutcome::Fail { .. }));
    }

    #[test]
    fn a_float_result_is_st0() {
        let s = spec(ValueType::Float(4), 1, Convention::Cdecl);
        let x = 1.25f32;
        let o = run(
            TWICE_FLOAT,
            &s,
            &case(0, &[x.to_bits()], 0, &(2.0 * x).to_le_bytes()),
        );
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: another value.
        let o = run(
            TWICE_FLOAT,
            &s,
            &case(0, &[x.to_bits()], 0, &(3.0 * x).to_le_bytes()),
        );
        assert!(matches!(o, CaseOutcome::Fail { .. }), "{o:?}");
    }

    #[test]
    fn an_8_byte_result_is_edx_eax() {
        let s = spec(ValueType::Int(8), 2, Convention::Cdecl);
        let o = run(WIDE, &s, &case(0, &[0x1111, 0x2222], 0x2222_0000_1111, &[]));
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: edx counts.
        let o = run(WIDE, &s, &case(0, &[0x1111, 0x2222], 0x1111, &[]));
        assert!(matches!(o, CaseOutcome::Fail { .. }), "{o:?}");
    }

    #[test]
    fn a_c_runtime_import_takes_its_arguments_from_the_stack() {
        let s = spec(ValueType::Void, 2, Convention::Cdecl);
        let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let c = with_region(
            with_region(
                case(0, &[STRUCT_AT, SRC_AT], 0, &[]),
                0,
                STRUCT_AT,
                &[0; 8],
                &src,
            ),
            1,
            SRC_AT,
            &src,
            &src,
        );
        let o = run(COPY8, &s, &c);
        assert!(matches!(o, CaseOutcome::Pass { .. }), "{o:?}");
        // Negative: what was recorded as written isn't what memcpy copies.
        let c = with_region(
            with_region(
                case(0, &[STRUCT_AT, SRC_AT], 0, &[]),
                0,
                STRUCT_AT,
                &[0; 8],
                &[9; 8],
            ),
            1,
            SRC_AT,
            &src,
            &src,
        );
        assert!(matches!(run(COPY8, &s, &c), CaseOutcome::Fail { .. }));
    }
}
