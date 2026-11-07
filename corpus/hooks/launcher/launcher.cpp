// Launcher for the M4 hook-repair loop (corpus/hooks/README.md).
//
//   launcher.exe <hookdll.dll> <manifest.toml> <trace.jsonl> <app.exe> [app args...]
//
// Starts the app suspended with the hook DLL added to its import table (DetourCreateProcessWithDllExW, the
// standard Detours injection path), so the DLL attaches its detours before the app's own code runs. It passes
// the manifest and trace paths and the SHA-256 of the app's .exe (its build id, the same one `pbeta analyze`
// records) through the environment, waits, and exits with the app's exit code. A crash shows up as an NTSTATUS
// exit code (e.g. 0xC0000005) and a trace without an "end" event.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#include <detours.h>

#include <cstdio>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

bool sha256_file(const wchar_t* path, std::string& hex) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
              BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0;
    std::vector<unsigned char> buf(1 << 16);
    DWORD n = 0;
    while (ok && ReadFile(file, buf.data(), static_cast<DWORD>(buf.size()), &n, nullptr) && n > 0) {
        ok = BCryptHashData(hash, buf.data(), n, 0) == 0;
    }
    unsigned char digest[32];
    ok = ok && BCryptFinishHash(hash, digest, sizeof digest, 0) == 0;
    if (hash) {
        BCryptDestroyHash(hash);
    }
    if (alg) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    CloseHandle(file);
    if (ok) {
        static const char digits[] = "0123456789abcdef";
        hex.clear();
        for (unsigned char b : digest) {
            hex += digits[b >> 4];
            hex += digits[b & 15];
        }
    }
    return ok;
}

std::string narrow(const wchar_t* s) {
    int n = WideCharToMultiByte(CP_ACP, 0, s, -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? n - 1 : 0, '\0');
    if (n > 1) {
        WideCharToMultiByte(CP_ACP, 0, s, -1, out.data(), n, nullptr, nullptr);
    }
    return out;
}

std::wstring full_path(const wchar_t* p) {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetFullPathNameW(p, MAX_PATH * 2, buf, nullptr);
    return n > 0 && n < MAX_PATH * 2 ? std::wstring(buf, n) : std::wstring(p);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 5) {
        std::fprintf(stderr, "usage: launcher <hookdll.dll> <manifest.toml> <trace.jsonl> <app.exe> [args...]\n");
        return 2;
    }
    std::wstring dll = full_path(argv[1]);
    std::wstring manifest = full_path(argv[2]);
    std::wstring trace = full_path(argv[3]);
    std::wstring app = full_path(argv[4]);

    std::string build;
    if (!sha256_file(app.c_str(), build)) {
        std::fprintf(stderr, "launcher: cannot hash %ls\n", app.c_str());
        return 2;
    }
    SetEnvironmentVariableW(L"PBETA_HOOKS", manifest.c_str());
    SetEnvironmentVariableW(L"PBETA_TRACE", trace.c_str());
    SetEnvironmentVariableA("PBETA_BUILD", build.c_str());
    DeleteFileW(trace.c_str());  // a stale trace must not pass for this run's

    std::wstring cmdline = L"\"" + app + L"\"";
    for (int i = 5; i < argc; i++) {
        cmdline += L" \"";
        cmdline += argv[i];
        cmdline += L"\"";
    }

    std::string dll_a = narrow(dll.c_str());
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!DetourCreateProcessWithDllExW(app.c_str(), cmdline.data(), nullptr, nullptr, TRUE,
            CREATE_DEFAULT_ERROR_MODE, nullptr, nullptr, &si, &pi, dll_a.c_str(), nullptr)) {
        std::fprintf(stderr, "launcher: DetourCreateProcessWithDllExW failed: %lu\n", GetLastError());
        return 2;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}
