; Generic hook thunk for the hook host on x86 (pbeta_host.cpp built for 32-bit; host_thunk.asm is the x64 one).
;
; Detours attaches pbeta_host_thunkN to the Nth hook with a built-in action. Each entry stub pushes N (no register
; is free on x86: MSVC passes arguments in ecx and edx, and whole-program builds in other registers too) and jumps
; to pbeta_host_common, which, in an ebp frame:
;   1. saves ecx, edx and eax into a HostFrame below ebp, with N and the entry esp (where the return address is);
;   2. calls pbeta_host_before(frame): it returns the original function (the Detours trampoline), or 0 when the
;      original isn't to be called, in which case it has already put the result in the frame (eax, edx, st(0)) and
;      how many bytes of arguments to remove (the calling convention's, from the config);
;   3. when there is an original: pushes copies of the caller's first MAX_STACK_WORDS stack words, restores ecx,
;      edx and eax, calls it, and saves eax, edx and (for a floating-point result) st(0), and how many bytes the
;      original removed from the copies: what this thunk must remove from the caller's stack too, whatever the
;      calling convention;
;   4. calls pbeta_host_after(frame), and returns the frame's eax, edx and st(0) to the caller, removing that many
;      bytes of arguments.
; ebx, esi and edi are never touched. Functions with more than MAX_STACK_WORDS stack words, and variadic functions,
; aren't supported: `pbeta host-config` refuses built-in actions on them.
;
; The HostFrame offsets below must match struct HostFrame in pbeta_host.cpp (static_asserts there).

.686
.model flat, C

EXTERN pbeta_host_before:PROC
EXTERN pbeta_host_after:PROC

MAX_STACK_WORDS EQU 32

F_ECX           EQU 00h
F_EDX           EQU 04h
F_EAX           EQU 08h
F_SLOT          EQU 0Ch         ; N
F_ESP           EQU 10h         ; esp at entry: [esp] is the return address, stack arguments start at +4
F_RES_EAX       EQU 14h
F_RES_EDX       EQU 18h
F_ST0           EQU 1Ch         ; st(0) as a double, for a floating-point result
F_POPS          EQU 24h         ; bytes of arguments to remove when returning
F_FLOAT         EQU 28h         ; nonzero: the result is in st(0)
F_CALL          EQU 2Ch         ; the C++ side's per-call state
F_ORIG          EQU 30h         ; the original, while calling it
F_ESP_CALL      EQU 34h         ; esp just before calling the original
FRAME_BYTES     EQU 38h

FR              EQU <ebp - FRAME_BYTES>

.code

pbeta_host_common PROC
    ; [esp] = N, [esp+4] = the return address, [esp+8] = the stack arguments
    push    ebp
    mov     ebp, esp                                    ; [ebp+4] = N, [ebp+8] = the return address
    sub     esp, FRAME_BYTES

    mov     [FR + F_ECX], ecx
    mov     [FR + F_EDX], edx
    mov     [FR + F_EAX], eax
    mov     eax, [ebp + 4]
    mov     [FR + F_SLOT], eax
    lea     eax, [ebp + 8]
    mov     [FR + F_ESP], eax
    xor     eax, eax
    mov     [FR + F_RES_EAX], eax
    mov     [FR + F_RES_EDX], eax
    mov     [FR + F_ST0], eax
    mov     [FR + F_ST0 + 4], eax
    mov     [FR + F_POPS], eax
    mov     [FR + F_FLOAT], eax
    mov     [FR + F_CALL], eax
    mov     [FR + F_ORIG], eax

    lea     eax, [FR]
    push    eax
    call    pbeta_host_before
    add     esp, 4
    test    eax, eax
    jz      done
    mov     [FR + F_ORIG], eax

    mov     ecx, [FR + F_ESP]
    i = MAX_STACK_WORDS - 1
    REPT MAX_STACK_WORDS
        push    dword ptr [ecx + 4 + i * 4]
        i = i - 1
    ENDM
    mov     [FR + F_ESP_CALL], esp
    mov     ecx, [FR + F_ECX]
    mov     edx, [FR + F_EDX]
    mov     eax, [FR + F_EAX]
    call    dword ptr [FR + F_ORIG]

    mov     [FR + F_RES_EAX], eax
    mov     [FR + F_RES_EDX], edx
    mov     eax, esp
    sub     eax, [FR + F_ESP_CALL]
    mov     [FR + F_POPS], eax
    cmp     dword ptr [FR + F_FLOAT], 0
    je      done
    fstp    qword ptr [FR + F_ST0]                      ; the x87 stack is empty again while C++ runs

done:
    lea     esp, [FR]
    lea     eax, [FR]
    push    eax
    call    pbeta_host_after
    add     esp, 4

    mov     eax, [FR + F_RES_EAX]
    mov     edx, [FR + F_RES_EDX]
    mov     ecx, [FR + F_POPS]
    cmp     dword ptr [FR + F_FLOAT], 0
    je      no_float
    fld     qword ptr [FR + F_ST0]
no_float:
    mov     esp, ebp
    pop     ebp                                         ; [esp] = N, [esp+4] = the return address
    add     esp, 4
    ; Move the return address up over the arguments to remove, and return there.
    push    eax
    mov     eax, [esp + 4]
    mov     [esp + 4 + ecx], eax
    pop     eax
    add     esp, ecx
    ret
pbeta_host_common ENDP

THUNK MACRO n
pbeta_host_thunk&n& PROC
    push    n
    jmp     pbeta_host_common
pbeta_host_thunk&n& ENDP
ENDM

; kThunks in pbeta_host.cpp.
j = 0
REPT 64
    THUNK %j
    j = j + 1
ENDM

THUNK_ADDR MACRO n
    DD pbeta_host_thunk&n&
ENDM

.const
PUBLIC pbeta_host_thunks
pbeta_host_thunks LABEL DWORD
j = 0
REPT 64
    THUNK_ADDR %j
    j = j + 1
ENDM

END
