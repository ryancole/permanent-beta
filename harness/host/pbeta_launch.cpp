// Starts a program with the pbeta hook host injected (harness/host/README.md).
//
//   pbeta-launch [--log <file>] <host-config.toml> <app.exe> [app args...]
//
// pbeta-host.dll is taken from this launcher's folder. The app starts suspended with the host added to its import
// table (Detours' DetourCreateProcessWithDllExW), so the hooks are attached before the app's own code runs. The
// config and log paths reach the host through PBETA_HOST_CONFIG and PBETA_HOST_LOG (default log:
// pbeta-host.log next to the config). Waits for the app and exits with its exit code.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

#include <cstdio>
#include <string>

namespace {

std::wstring full_path(const wchar_t* p) {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetFullPathNameW(p, MAX_PATH * 2, buf, nullptr);
    return n > 0 && n < MAX_PATH * 2 ? std::wstring(buf, n) : std::wstring(p);
}

int usage() {
    std::fprintf(stderr, "usage: pbeta-launch [--log <file>] <host-config.toml> <app.exe> [app args...]\n");
    return 2;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    int i = 1;
    std::wstring log;
    if (i + 1 < argc && std::wstring(argv[i]) == L"--log") {
        log = full_path(argv[i + 1]);
        i += 2;
    }
    if (argc - i < 2) {
        return usage();
    }
    std::wstring config = full_path(argv[i]);
    std::wstring app = full_path(argv[i + 1]);
    if (GetFileAttributesW(config.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr, "pbeta-launch: no host config at %ls\n", config.c_str());
        return 2;
    }

    wchar_t me[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, me, ARRAYSIZE(me));
    std::wstring dir(me);
    dir = dir.substr(0, dir.find_last_of(L"\\/") + 1);
    std::wstring host = dir + L"pbeta-host.dll";
    if (GetFileAttributesW(host.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fprintf(stderr, "pbeta-launch: no pbeta-host.dll next to the launcher (%ls)\n", host.c_str());
        return 2;
    }

    SetEnvironmentVariableW(L"PBETA_HOST_CONFIG", config.c_str());
    SetEnvironmentVariableW(L"PBETA_HOST_LOG", log.empty() ? nullptr : log.c_str());

    std::wstring cmdline = L"\"" + app + L"\"";
    for (int a = i + 2; a < argc; a++) {
        cmdline += L" \"";
        cmdline += argv[a];
        cmdline += L"\"";
    }
    char host_a[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_ACP, 0, host.c_str(), -1, host_a, sizeof host_a - 1, nullptr, nullptr);

    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!DetourCreateProcessWithDllExW(app.c_str(), cmdline.data(), nullptr, nullptr, TRUE,
            CREATE_DEFAULT_ERROR_MODE, nullptr, nullptr, &si, &pi, host_a, nullptr)) {
        std::fprintf(stderr, "pbeta-launch: can't start %ls: error %lu\n", app.c_str(), GetLastError());
        return 2;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
}
