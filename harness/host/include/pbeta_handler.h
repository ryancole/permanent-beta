// Handler DLLs for the pbeta hook host (harness/host/README.md).
//
// A handler is your code for one hooked function. The host attaches it in the original's place, in whichever build
// it's loaded into, and fills in a pointer to the original. A handler DLL needs no Detours and knows no addresses:
//
//     #include <pbeta_handler.h>
//
//     PBETA_HOOK(BOOL, CenterWindow, (HWND hWnd)) {
//         pbeta_log("centering %p", hWnd);
//         return PBETA_ORIGINAL(CenterWindow)(hWnd);
//     }
//
// and in the hook manifest: `detour = "myhandlers.dll!CenterWindow"`. The handler's prototype must match the hooked
// function's exactly (same parameters and return type); nothing can check that for you.
//
// PBETA_HOOK(ret, name, params) exports `name` (the handler) and `pbeta_original_<name>`, a pointer the host sets
// to the original before the first call. PBETA_ORIGINAL(name) is that pointer.
//
// In a 32-bit (x86) program the handler must also use the hooked function's calling convention:
// PBETA_HOOK_CC(ret, convention, name, params), e.g. PBETA_HOOK_CC(int, __stdcall, Area, (int w, int h)). MSVC
// allows __thiscall on member functions only, so a member function's handler is __fastcall with an unused second
// parameter, which passes the same way (`this` in ecx, edx unused, the rest on the stack):
//
//     PBETA_HOOK_CC(int, __fastcall, Shape_Area, (Shape* self, void* edx_unused, int scale)) {
//         return PBETA_ORIGINAL(Shape_Area)(self, edx_unused, scale);
//     }
//
// `pbeta handler-stubs` writes these. On x64 there is one convention, and the keyword is ignored.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdarg>

#define PBETA_HOOK(ret, name, params)                                                 \
    extern "C" __declspec(dllexport) ret(*pbeta_original_##name) params = nullptr; \
    extern "C" __declspec(dllexport) ret name params

#define PBETA_HOOK_CC(ret, cc, name, params)                                                \
    extern "C" __declspec(dllexport) ret(cc* pbeta_original_##name) params = nullptr; \
    extern "C" __declspec(dllexport) ret cc name params

#define PBETA_ORIGINAL(name) pbeta_original_##name

// Writes a line to the host's log (printf-style). Does nothing if the host isn't loaded.
inline void pbeta_log(const char* fmt, ...) {
    using VLog = void (*)(const char*, va_list);
    static VLog vlog = [] {
        HMODULE host = GetModuleHandleW(L"pbeta-host.dll");
        return host ? reinterpret_cast<VLog>(GetProcAddress(host, "pbeta_host_vlog")) : nullptr;
    }();
    if (!vlog) {
        return;
    }
    va_list args;
    va_start(args, fmt);
    vlog(fmt, args);
    va_end(args);
}
