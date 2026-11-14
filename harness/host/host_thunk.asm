; Generic hook thunk for the hook host (pbeta_host.cpp). Adapted from the record thunk
; (corpus/hooks/hookdll/record_thunk.asm), with one difference: the host may decide not to call the original.
;
; Detours attaches pbeta_host_thunkN to the Nth hook with a built-in action. Each entry stub puts N in rax (volatile,
; never an argument register in Win64) and jumps to pbeta_host_common, which:
;   1. saves rcx, rdx, r8, r9 and xmm0-xmm3 into a HostFrame on its own stack, with N and the entry rsp;
;   2. calls pbeta_host_before(frame): it returns the original function (the Detours trampoline), or 0 when the
;      original isn't to be called, in which case it has already put the result in the frame's rax / xmm0;
;   3. when there is an original: copies the caller's first MAX_STACK_ARGS stack arguments into its own outgoing
;      area, restores the argument registers, calls it and saves its rax and xmm0 into the frame;
;   4. calls pbeta_host_after(frame), and returns the frame's rax and xmm0 to the caller.
; Nonvolatile registers are never touched. Functions with more than MAX_STACK_ARGS stack arguments, and variadic
; functions, aren't supported: `pbeta host-config` refuses built-in actions on them.
;
; The HostFrame offsets below must match struct HostFrame in pbeta_host.cpp (static_asserts there).

EXTERN pbeta_host_before:PROC
EXTERN pbeta_host_after:PROC

MAX_STACK_ARGS  EQU 8

F_GPR           EQU 00h         ; rcx, rdx, r8, r9
F_XMM           EQU 20h         ; xmm0-xmm3, 16 bytes each
F_SLOT          EQU 60h         ; N
F_RSP           EQU 68h         ; rsp at entry: [rsp] is the return address, stack arguments start at +28h
F_RAX           EQU 70h         ; result rax
F_XMM0          EQU 78h         ; result xmm0
F_CALL          EQU 88h         ; the C++ side's per-call state
FRAME_BYTES     EQU 90h

OUT_ARGS        EQU 20h                                 ; after the callee's shadow space
REC             EQU OUT_ARGS + MAX_STACK_ARGS * 8       ; 60h
STACK_SIZE      EQU 0F8h        ; >= REC + FRAME_BYTES, and 8 mod 16 so calls see an aligned stack

.code

pbeta_host_common PROC FRAME
    sub     rsp, STACK_SIZE
    .allocstack STACK_SIZE
    .endprolog

    mov     [rsp + REC + F_GPR + 00h], rcx
    mov     [rsp + REC + F_GPR + 08h], rdx
    mov     [rsp + REC + F_GPR + 10h], r8
    mov     [rsp + REC + F_GPR + 18h], r9
    movdqu  [rsp + REC + F_XMM + 00h], xmm0
    movdqu  [rsp + REC + F_XMM + 10h], xmm1
    movdqu  [rsp + REC + F_XMM + 20h], xmm2
    movdqu  [rsp + REC + F_XMM + 30h], xmm3
    mov     [rsp + REC + F_SLOT], rax
    lea     rax, [rsp + STACK_SIZE]
    mov     [rsp + REC + F_RSP], rax
    xor     eax, eax
    mov     [rsp + REC + F_RAX], rax
    mov     [rsp + REC + F_XMM0], rax
    mov     [rsp + REC + F_XMM0 + 8], rax
    mov     [rsp + REC + F_CALL], rax

    lea     rcx, [rsp + REC]
    call    pbeta_host_before
    test    rax, rax
    jz      no_call
    mov     r11, rax                                    ; the original function

    mov     r10, [rsp + REC + F_RSP]
    i = 0
    REPT MAX_STACK_ARGS
        mov     rax, [r10 + 28h + i * 8]
        mov     [rsp + OUT_ARGS + i * 8], rax
        i = i + 1
    ENDM

    mov     rcx, [rsp + REC + F_GPR + 00h]
    mov     rdx, [rsp + REC + F_GPR + 08h]
    mov     r8,  [rsp + REC + F_GPR + 10h]
    mov     r9,  [rsp + REC + F_GPR + 18h]
    movdqu  xmm0, [rsp + REC + F_XMM + 00h]
    movdqu  xmm1, [rsp + REC + F_XMM + 10h]
    movdqu  xmm2, [rsp + REC + F_XMM + 20h]
    movdqu  xmm3, [rsp + REC + F_XMM + 30h]
    call    r11

    mov     [rsp + REC + F_RAX], rax
    movdqu  [rsp + REC + F_XMM0], xmm0

no_call:
    lea     rcx, [rsp + REC]
    call    pbeta_host_after

    mov     rax, [rsp + REC + F_RAX]
    movdqu  xmm0, [rsp + REC + F_XMM0]
    add     rsp, STACK_SIZE
    ret
pbeta_host_common ENDP

; Entry stubs: leaf code that doesn't touch the stack, so it needs no unwind information.
THUNK MACRO n
pbeta_host_thunk&n& PROC
    mov     eax, n
    jmp     pbeta_host_common
pbeta_host_thunk&n& ENDP
ENDM

; HOST_THUNKS in pbeta_host.cpp.
j = 0
REPT 64
    THUNK %j
    j = j + 1
ENDM

THUNK_ADDR MACRO n
    DQ pbeta_host_thunk&n&
ENDM

.const
PUBLIC pbeta_host_thunks
pbeta_host_thunks LABEL QWORD
j = 0
REPT 64
    THUNK_ADDR %j
    j = j + 1
ENDM

END
