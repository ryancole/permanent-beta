; Generic register-capturing thunk for the hook DLL's record mode (design §7.3; hookdll.cpp, "Record mode").
;
; Detours attaches pbeta_record_thunkN to the Nth recorded hook. Each entry stub puts N in rax (volatile, never an
; argument register in Win64) and jumps to pbeta_record_common, which:
;   1. saves rcx, rdx, r8, r9 and xmm0-xmm3 into a RecordFrame on its own stack, with N and the entry rsp;
;   2. calls pbeta_record_before(frame): it captures the arguments' memory and returns the original function
;      (the Detours trampoline);
;   3. copies the caller's first MAX_STACK_ARGS stack arguments into its own outgoing area, restores the argument
;      registers and calls the original;
;   4. saves rax and xmm0 into the frame, calls pbeta_record_after(frame) (memory again, then the test case), and
;      returns the original's rax and xmm0 to the caller.
; Nonvolatile registers are never touched. Variadic functions and functions with more than MAX_STACK_ARGS stack
; arguments aren't supported (their extra stack arguments wouldn't be forwarded).
;
; The RecordFrame offsets below must match struct RecordFrame in hookdll.cpp (static_asserts there).

EXTERN pbeta_record_before:PROC
EXTERN pbeta_record_after:PROC

MAX_STACK_ARGS  EQU 8

F_GPR           EQU 00h         ; rcx, rdx, r8, r9
F_XMM           EQU 20h         ; xmm0-xmm3, 16 bytes each
F_SLOT          EQU 60h         ; N
F_RSP           EQU 68h         ; rsp at entry: [rsp] is the return address, stack arguments start at +28h
F_RAX           EQU 70h         ; returned rax
F_XMM0          EQU 78h         ; returned xmm0
F_CALL          EQU 88h         ; the C++ side's per-call state
FRAME_BYTES     EQU 90h

OUT_ARGS        EQU 20h                                 ; after the callee's shadow space
REC             EQU OUT_ARGS + MAX_STACK_ARGS * 8       ; 60h
STACK_SIZE      EQU 0F8h        ; >= REC + FRAME_BYTES, and 8 mod 16 so calls see an aligned stack

.code

pbeta_record_common PROC FRAME
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
    mov     qword ptr [rsp + REC + F_CALL], 0

    lea     rcx, [rsp + REC]
    call    pbeta_record_before
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
    lea     rcx, [rsp + REC]
    call    pbeta_record_after

    mov     rax, [rsp + REC + F_RAX]
    movdqu  xmm0, [rsp + REC + F_XMM0]
    add     rsp, STACK_SIZE
    ret
pbeta_record_common ENDP

; Entry stubs: leaf code that doesn't touch the stack, so it needs no unwind information.
THUNK MACRO n
pbeta_record_thunk&n& PROC
    mov     eax, n
    jmp     pbeta_record_common
pbeta_record_thunk&n& ENDP
ENDM

THUNK 0
THUNK 1
THUNK 2
THUNK 3
THUNK 4
THUNK 5
THUNK 6
THUNK 7
THUNK 8
THUNK 9
THUNK 10
THUNK 11
THUNK 12
THUNK 13
THUNK 14
THUNK 15

END
