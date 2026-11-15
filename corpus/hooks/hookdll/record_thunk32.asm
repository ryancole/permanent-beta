; Generic register-capturing thunk for the hook DLL's record mode on x86 (hookdll.cpp built for 32-bit, "Record
; mode"; record_thunk.asm is the x64 one). Modelled on harness/host/host_thunk32.asm.
;
; Detours attaches pbeta_record_thunkN to the Nth recorded hook. Each entry stub pushes N (no register is free on
; x86: MSVC passes arguments in ecx and edx) and jumps to pbeta_record_common, which, in an ebp frame:
;   1. saves ecx, edx and eax into a RecordFrame below ebp, with N and the entry esp (where the return address is);
;   2. calls pbeta_record_before(frame): it captures the arguments' memory and returns the original function (the
;      Detours trampoline);
;   3. pushes copies of the caller's first MAX_STACK_WORDS stack words, restores ecx, edx and eax and calls the
;      original; saves eax and edx, and how many bytes the original removed from the copies: what this thunk must
;      remove from the caller's stack too, whatever the calling convention;
;   4. if the original left a value on the x87 stack (fxam: st(0) isn't empty), saves st(0) as a float, a double
;      and in full (80 bits) and pops it, so the x87 stack is empty while C++ runs;
;   5. calls pbeta_record_after(frame) (memory again, then the test case), loads st(0) back in full, and returns
;      eax and edx to the caller, removing that many bytes of arguments.
; ebx, esi and edi are never touched. Functions with more than MAX_STACK_WORDS stack words, and variadic calls
; passing more, aren't supported (their extra words wouldn't be forwarded).
;
; pbeta_import_thunkN / pbeta_import_common do the same for the app's import calls: the DLL points the Nth patched
; import address table slot at pbeta_import_thunkN, and pbeta_import_before / pbeta_import_after record the call
; when it happens inside a recorded call (hookdll.cpp, "Import calls").
;
; The RecordFrame offsets below must match struct RecordFrame in hookdll.cpp (static_asserts there).

.686
.model flat, C

EXTERN pbeta_record_before:PROC
EXTERN pbeta_record_after:PROC
EXTERN pbeta_import_before:PROC
EXTERN pbeta_import_after:PROC

MAX_STACK_WORDS EQU 32

F_ECX           EQU 00h
F_EDX           EQU 04h
F_EAX           EQU 08h
F_SLOT          EQU 0Ch         ; N
F_ESP           EQU 10h         ; esp at entry: [esp] is the return address, stack arguments start at +4
F_RES_EAX       EQU 14h
F_RES_EDX       EQU 18h
F_ST0_F         EQU 1Ch         ; st(0) as a float
F_ST0_D         EQU 20h         ; st(0) as a double
F_ST0_X         EQU 28h         ; st(0) in full (10 bytes), to load back
F_POPS          EQU 34h         ; bytes of arguments the original removed
F_FLOAT         EQU 38h         ; nonzero: the original left a value in st(0)
F_CALL          EQU 3Ch         ; the C++ side's per-call state
F_ORIG          EQU 40h         ; the original, while calling it
F_ESP_CALL      EQU 44h         ; esp just before calling the original
FRAME_BYTES     EQU 48h

FR              EQU <ebp - FRAME_BYTES>

.code

; The common body, parameterized by the before/after callbacks.
COMMON MACRO procname, before, after
    LOCAL no_float, no_reload
procname PROC
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
    mov     [FR + F_ST0_F], eax
    mov     [FR + F_ST0_D], eax
    mov     [FR + F_ST0_D + 4], eax
    mov     [FR + F_POPS], eax
    mov     [FR + F_FLOAT], eax
    mov     [FR + F_CALL], eax

    lea     eax, [FR]
    push    eax
    call    before
    add     esp, 4
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

    ; st(0) empty: C3 = 1, C2 = 0, C0 = 1.
    fxam
    fnstsw  ax
    and     ax, 4500h
    cmp     ax, 4100h
    je      no_float
    mov     dword ptr [FR + F_FLOAT], 1
    fst     dword ptr [FR + F_ST0_F]
    fst     qword ptr [FR + F_ST0_D]
    fstp    tbyte ptr [FR + F_ST0_X]                    ; the x87 stack is empty again while C++ runs
no_float:

    lea     esp, [FR]
    lea     eax, [FR]
    push    eax
    call    after
    add     esp, 4

    cmp     dword ptr [FR + F_FLOAT], 0
    je      no_reload
    fld     tbyte ptr [FR + F_ST0_X]
no_reload:
    mov     eax, [FR + F_RES_EAX]
    mov     edx, [FR + F_RES_EDX]
    mov     ecx, [FR + F_POPS]
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
procname ENDP
ENDM

COMMON pbeta_record_common, pbeta_record_before, pbeta_record_after
COMMON pbeta_import_common, pbeta_import_before, pbeta_import_after

THUNK MACRO n
pbeta_record_thunk&n& PROC
    push    n
    jmp     pbeta_record_common
pbeta_record_thunk&n& ENDP
ENDM

; kThunks in hookdll.cpp.
j = 0
REPT 16
    THUNK %j
    j = j + 1
ENDM

IMPORT_THUNK MACRO n
pbeta_import_thunk&n& PROC
    push    n
    jmp     pbeta_import_common
pbeta_import_thunk&n& ENDP
ENDM

; kImportThunks in hookdll.cpp.
j = 0
REPT 256
    IMPORT_THUNK %j
    j = j + 1
ENDM

THUNK_ADDR MACRO n
    DD pbeta_import_thunk&n&
ENDM

; The import thunks' addresses, for the DLL to put in the import address table.
.const
PUBLIC pbeta_import_thunks
pbeta_import_thunks LABEL DWORD
j = 0
REPT 256
    THUNK_ADDR %j
    j = j + 1
ENDM

END
