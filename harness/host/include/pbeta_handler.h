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

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdarg>

#define PBETA_HOOK(ret, name, params)                                                 \
    extern "C" __declspec(dllexport) ret(*pbeta_original_##name) params = nullptr; \
    extern "C" __declspec(dllexport) ret name params

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
