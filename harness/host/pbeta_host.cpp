// pbeta hook host (harness/host/README.md): one Detours DLL for any x64 program.
//
// On load it hashes the executable it was loaded into (SHA-256, the build id `pbeta analyze` records), reads the
// host config (`pbeta host-config`) and attaches every hook listed for that build:
//
// - at its RVA, only after the code there matches the hook's pattern (when it has one);
// - with a built-in action (`log`, `skip`, `return <n>`) through the generic thunk (host_thunk.asm), which needs no
//   code per prototype; or
// - with a handler (`<file.dll>!<export>`, include/pbeta_handler.h): the DLL is loaded from the config's folder and
//   its function attached in the original's place, its `pbeta_original_<export>` set to the original.
//
// A build the config doesn't list gets no hooks at all: the program runs as it would without the host.
//
// Configuration, from the environment (pbeta-launch sets both):
//   PBETA_HOST_CONFIG  the host config (default: pbeta-host.toml next to this DLL)
//   PBETA_HOST_LOG     the log, appended to (default: pbeta-host.log next to the config)
//
// Log lines: `CenterWindow(hWnd=0x00000000000a02ba) -> 1`, `... -> 1 (skipped: returned without calling it)`.
// Arguments are decoded by the hook's prototype; without one the four integer argument registers are shown.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#include <detours.h>

#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// Detours needs ordinal 1 in a DLL it injects (DetourCreateProcessWithDllEx).
#pragma comment(linker, "/export:DetourFinishHelperProcess,@1,NONAME")

namespace {

// ---------------------------------------------------------------------------------------------------------------
// Log

FILE* g_log = nullptr;
CRITICAL_SECTION g_lock;

void write_line(const std::string& line) {
    if (!g_log) {
        return;
    }
    EnterCriticalSection(&g_lock);
    std::fputs(line.c_str(), g_log);
    std::fputc('\n', g_log);
    std::fflush(g_log);  // a crash must not lose the calls before it
    LeaveCriticalSection(&g_lock);
}

std::string vformat(const char* fmt, va_list args) {
    va_list copy;
    va_copy(copy, args);
    int n = std::vsnprintf(nullptr, 0, fmt, copy);
    va_end(copy);
    if (n <= 0) {
        return std::string();
    }
    std::string out(static_cast<size_t>(n) + 1, '\0');
    std::vsnprintf(out.data(), out.size(), fmt, args);
    out.resize(static_cast<size_t>(n));
    return out;
}

void log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    write_line(vformat(fmt, args));
    va_end(args);
}

std::string hex(unsigned long long v) {
    char buf[24];
    std::snprintf(buf, sizeof buf, "0x%llx", v);
    return buf;
}

// ---------------------------------------------------------------------------------------------------------------
// Config: the TOML subset `pbeta host-config` writes ([[hook]], [[hook.arg]], key = "string" | integer, comments)

struct HostArg {
    std::string slot, name, type, value, show;
};

struct HostHook {
    std::string build, name, rva, pattern, action, prototype, ret;
    std::vector<HostArg> args;
};

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
}

// Value of `key = value`: a basic string (with escapes), a literal string, or a bare token up to a comment.
std::string toml_value(const std::string& raw) {
    std::string v = trim(raw);
    if (!v.empty() && v[0] == '"') {
        std::string out;
        for (size_t i = 1; i < v.size() && v[i] != '"'; i++) {
            if (v[i] == '\\' && i + 1 < v.size()) {
                i++;
            }
            out += v[i];
        }
        return out;
    }
    if (!v.empty() && v[0] == '\'') {
        size_t end = v.find('\'', 1);
        return v.substr(1, end == std::string::npos ? std::string::npos : end - 1);
    }
    size_t hash = v.find('#');
    return trim(hash == std::string::npos ? v : v.substr(0, hash));
}

bool parse_config(const std::wstring& path, std::vector<HostHook>& hooks) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) {
        return false;
    }
    std::string section;
    char buf[8192];
    while (std::fgets(buf, sizeof buf, f)) {
        std::string line = trim(buf);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line == "[[hook]]") {
            hooks.emplace_back();
            section = "hook";
            continue;
        }
        if (line == "[[hook.arg]]") {
            if (!hooks.empty()) {
                hooks.back().args.emplace_back();
            }
            section = "arg";
            continue;
        }
        if (line[0] == '[') {
            section = "other";
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos || hooks.empty()) {
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string value = toml_value(line.substr(eq + 1));
        HostHook& h = hooks.back();
        if (section == "hook") {
            if (key == "build") h.build = value;
            else if (key == "name") h.name = value;
            else if (key == "rva") h.rva = value;
            else if (key == "pattern") h.pattern = value;
            else if (key == "action") h.action = value;
            else if (key == "prototype") h.prototype = value;
            else if (key == "ret") h.ret = value;
        } else if (section == "arg" && !h.args.empty()) {
            HostArg& a = h.args.back();
            if (key == "slot") a.slot = value;
            else if (key == "name") a.name = value;
            else if (key == "type") a.type = value;
            else if (key == "value") a.value = value;
            else if (key == "show") a.show = value;
        }
    }
    std::fclose(f);
    return true;
}

// ---------------------------------------------------------------------------------------------------------------
// Reading memory that may not be readable

bool safe_copy(void* dst, const void* src, size_t n) {
    __try {
        std::memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Up to max characters of a NUL-terminated string of `width`-byte units; false if unreadable.
bool safe_string(const void* p, size_t width, size_t max, std::vector<unsigned short>& out) {
    out.clear();
    for (size_t i = 0; i < max; i++) {
        unsigned short c = 0;
        if (!safe_copy(&c, static_cast<const char*>(p) + i * width, width)) {
            return false;
        }
        if (c == 0) {
            return true;
        }
        out.push_back(c);
    }
    return true;
}

// ---------------------------------------------------------------------------------------------------------------
// Sites: one per attached hook

// Must match host_thunk.asm.
struct HostFrame {
    unsigned long long gpr[4];      // rcx, rdx, r8, r9
    unsigned char xmm[4][16];       // xmm0-xmm3
    unsigned long long slot;        // which site
    unsigned long long entry_rsp;   // [entry_rsp] is the return address
    unsigned long long rax;         // result
    unsigned char xmm0[16];         // result
    void* call;                     // per-call state (the call's log line)
};
static_assert(offsetof(HostFrame, xmm) == 0x20, "host_thunk.asm F_XMM");
static_assert(offsetof(HostFrame, slot) == 0x60, "host_thunk.asm F_SLOT");
static_assert(offsetof(HostFrame, entry_rsp) == 0x68, "host_thunk.asm F_RSP");
static_assert(offsetof(HostFrame, rax) == 0x70, "host_thunk.asm F_RAX");
static_assert(offsetof(HostFrame, xmm0) == 0x78, "host_thunk.asm F_XMM0");
static_assert(offsetof(HostFrame, call) == 0x88, "host_thunk.asm F_CALL");
static_assert(sizeof(HostFrame) == 0x90, "host_thunk.asm FRAME_BYTES");

enum class Kind { Log, Skip, Return };

struct Site {
    HostHook hook;
    Kind kind = Kind::Log;
    unsigned long long value = 0;  // Return
    PVOID original = nullptr;      // the Detours trampoline after attaching
};

constexpr int kThunks = 64;  // REPT count in host_thunk.asm
Site g_sites[kThunks];
int g_used = 0;

// The 64-bit value of an argument slot at entry (`rcx`, `xmm1`, `stack+0x28`).
bool slot_value(const HostFrame* f, const std::string& slot, unsigned long long& out) {
    static const char* const regs[] = {"rcx", "rdx", "r8", "r9"};
    for (int i = 0; i < 4; i++) {
        if (slot == regs[i]) {
            out = f->gpr[i];
            return true;
        }
    }
    if (slot.size() == 4 && slot.compare(0, 3, "xmm") == 0 && slot[3] >= '0' && slot[3] <= '3') {
        std::memcpy(&out, f->xmm[slot[3] - '0'], 8);
        return true;
    }
    if (slot.compare(0, 6, "stack+") == 0) {
        unsigned long long off = std::strtoull(slot.c_str() + 6, nullptr, 0);
        return safe_copy(&out, reinterpret_cast<const void*>(f->entry_rsp + off), 8);
    }
    return false;
}

std::string utf8(const std::vector<unsigned short>& units, bool wide) {
    std::string out;
    if (wide) {
        std::wstring w(units.begin(), units.end());
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        out.resize(n > 0 ? static_cast<size_t>(n) : 0);
        if (n > 0) {
            WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), out.data(), n, nullptr, nullptr);
        }
    } else {
        for (unsigned short c : units) {
            out += static_cast<char>(c);
        }
    }
    std::string escaped;
    for (char c : out) {
        if (c == '"' || c == '\\') {
            escaped += '\\';
            escaped += c;
        } else if (static_cast<unsigned char>(c) < 0x20) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\x%02x", static_cast<unsigned char>(c));
            escaped += buf;
        } else {
            escaped += c;
        }
    }
    return escaped;
}

// A value as the config's `value` says it travels: `int:4`, `float:8`, `pointer`, `void`, `unknown`.
std::string format_value(const std::string& kind, unsigned long long raw, const unsigned char* xmm) {
    if (kind.compare(0, 4, "int:") == 0) {
        int width = std::atoi(kind.c_str() + 4);
        long long v = 0;
        switch (width) {
            case 1: v = static_cast<signed char>(raw); break;
            case 2: v = static_cast<short>(raw); break;
            case 4: v = static_cast<int>(raw); break;
            default: v = static_cast<long long>(raw); break;
        }
        return std::to_string(v);
    }
    if (kind == "float:4" && xmm) {
        float v;
        std::memcpy(&v, xmm, 4);
        char buf[48];
        std::snprintf(buf, sizeof buf, "%g", v);
        return buf;
    }
    if (kind == "float:8" && xmm) {
        double v;
        std::memcpy(&v, xmm, 8);
        char buf[48];
        std::snprintf(buf, sizeof buf, "%g", v);
        return buf;
    }
    return hex(raw);
}

constexpr size_t kMaxText = 256;  // characters of a string argument shown

std::string format_args(const Site& s, const HostFrame* f) {
    std::string out = s.hook.name + "(";
    if (s.hook.prototype.empty()) {
        out += "rcx=" + hex(f->gpr[0]) + ", rdx=" + hex(f->gpr[1]) + ", r8=" + hex(f->gpr[2]) + ", r9=" + hex(f->gpr[3]);
        return out + ")";
    }
    bool first = true;
    for (const HostArg& a : s.hook.args) {
        if (!first) {
            out += ", ";
        }
        first = false;
        if (!a.name.empty()) {
            out += a.name + "=";
        }
        unsigned long long raw = 0;
        if (!slot_value(f, a.slot, raw)) {
            out += "?";
            continue;
        }
        const unsigned char* xmm = nullptr;
        if (a.slot.compare(0, 3, "xmm") == 0) {
            xmm = f->xmm[a.slot[3] - '0'];
        }
        out += format_value(a.value, raw, xmm);
        if (!a.show.empty() && raw != 0) {
            bool wide = a.show == "wstring";
            std::vector<unsigned short> units;
            if (safe_string(reinterpret_cast<const void*>(raw), wide ? 2 : 1, kMaxText, units)) {
                out += " \"" + utf8(units, wide) + (units.size() == kMaxText ? "\"..." : "\"");
            } else {
                out += " <unreadable>";
            }
        }
    }
    return out + ")";
}

std::string format_result(const Site& s, const HostFrame* f) {
    if (s.hook.ret == "void") {
        return "";
    }
    return " -> " + format_value(s.hook.ret.empty() ? "unknown" : s.hook.ret, f->rax, f->xmm0);
}

}  // namespace

extern "C" void* pbeta_host_before(HostFrame* f) {
    Site& s = g_sites[f->slot];
    f->call = new std::string(format_args(s, f));
    switch (s.kind) {
        case Kind::Log:
            return s.original;
        case Kind::Skip:
            f->rax = 0;
            return nullptr;
        case Kind::Return:
            f->rax = s.value;
            return nullptr;
    }
    return s.original;
}

extern "C" void pbeta_host_after(HostFrame* f) {
    Site& s = g_sites[f->slot];
    auto* line = static_cast<std::string*>(f->call);
    std::string out = (line ? *line : s.hook.name) + format_result(s, f);
    if (s.kind != Kind::Log) {
        out += " (" + s.hook.action + ": returned without calling it)";
    }
    write_line(out);
    delete line;
    f->call = nullptr;
}

// For handler DLLs (pbeta_log in include/pbeta_handler.h).
extern "C" __declspec(dllexport) void pbeta_host_vlog(const char* fmt, va_list args) {
    write_line(vformat(fmt, args));
}

extern "C" void* const pbeta_host_thunks[kThunks];

namespace {

bool sha256_file(const wchar_t* path, std::string& out) {
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }
    BCRYPT_HASH_HANDLE hash = nullptr;
    bool ok = BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, nullptr, 0, nullptr, 0, 0) == 0;
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
    CloseHandle(file);
    if (ok) {
        static const char digits[] = "0123456789abcdef";
        out.clear();
        for (unsigned char b : digest) {
            out += digits[b >> 4];
            out += digits[b & 15];
        }
    }
    return ok;
}

// Whether the bytes at `at` match an AOB pattern like "48 89 4C 24 ?? 55".
bool matches_pattern(const unsigned char* at, const std::string& pattern) {
    size_t i = 0;
    for (size_t p = 0; p < pattern.size();) {
        if (pattern[p] == ' ') {
            p++;
            continue;
        }
        unsigned char actual = 0;
        if (!safe_copy(&actual, at + i, 1)) {
            return false;
        }
        if (pattern[p] == '?') {
            p += (p + 1 < pattern.size() && pattern[p + 1] == '?') ? 2 : 1;
        } else {
            if (p + 1 >= pattern.size()) {
                return false;
            }
            char byte[3] = {pattern[p], pattern[p + 1], 0};
            if (static_cast<unsigned char>(std::strtoul(byte, nullptr, 16)) != actual) {
                return false;
            }
            p += 2;
        }
        i++;
    }
    return true;
}

std::wstring widen(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(n > 0 ? static_cast<size_t>(n - 1) : 0, L'\0');
    if (n > 1) {
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, out.data(), n);
    }
    return out;
}

std::wstring folder_of(const std::wstring& path) {
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : path.substr(0, slash + 1);
}

std::wstring env(const wchar_t* name) {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableW(name, buf, ARRAYSIZE(buf));
    return n > 0 && n < ARRAYSIZE(buf) ? std::wstring(buf, n) : std::wstring();
}

bool attach(PVOID* target, PVOID detour) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LONG err = DetourAttach(target, detour);
    if (err != NO_ERROR) {
        DetourTransactionAbort();
        return false;
    }
    return DetourTransactionCommit() == NO_ERROR;
}

// Loads `<config folder>\dll` and attaches its `export` at `at`, with `pbeta_original_<export>` as the original.
void attach_handler(const HostHook& h, unsigned char* at, const std::wstring& folder) {
    size_t bang = h.action.find('!');
    std::string dll = h.action.substr(0, bang);
    std::string exported = h.action.substr(bang + 1);
    std::wstring path = folder + widen(dll);
    HMODULE module = LoadLibraryW(path.c_str());
    if (!module) {
        log("%s: skipped (can't load %s: error %lu)", h.name.c_str(), dll.c_str(), GetLastError());
        return;
    }
    PVOID detour = reinterpret_cast<PVOID>(GetProcAddress(module, exported.c_str()));
    auto original = reinterpret_cast<PVOID*>(GetProcAddress(module, ("pbeta_original_" + exported).c_str()));
    if (!detour || !original) {
        log("%s: skipped (%s doesn't export %s and pbeta_original_%s: declare it with PBETA_HOOK)", h.name.c_str(),
            dll.c_str(), exported.c_str(), exported.c_str());
        return;
    }
    *original = at;
    bool ok = attach(original, detour);
    log("%s: %s at %s, handled by %s%s", h.name.c_str(), ok ? "attached" : "attach failed", h.rva.c_str(),
        h.action.c_str(), h.pattern.empty() ? "" : " (pattern checked)");
}

void attach_all(const std::wstring& config_path) {
    wchar_t exe[MAX_PATH * 2] = {};
    GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe));
    std::string build;
    if (!sha256_file(exe, build)) {
        log("can't hash %ls: no hooks attached", exe);
        return;
    }
    std::vector<HostHook> hooks;
    if (!parse_config(config_path, hooks)) {
        log("can't read the host config %ls: no hooks attached", config_path.c_str());
        return;
    }
    std::vector<const HostHook*> mine;
    for (const HostHook& h : hooks) {
        if (h.build == build) {
            mine.push_back(&h);
        }
    }
    log("%ls: build %s, %zu hook(s) in the config for it", exe, build.c_str(), mine.size());
    if (mine.empty()) {
        log("no hooks attached: run pbeta repair and pbeta host-config for this build");
        return;
    }
    auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    std::wstring folder = folder_of(config_path);
    for (const HostHook* hp : mine) {
        const HostHook& h = *hp;
        unsigned long long rva = std::strtoull(h.rva.c_str(), nullptr, 0);
        if (rva == 0) {
            log("%s: skipped (no RVA)", h.name.c_str());
            continue;
        }
        unsigned char* at = base + rva;
        if (!h.pattern.empty() && !matches_pattern(at, h.pattern)) {
            log("%s: skipped (the code at %s doesn't match its pattern)", h.name.c_str(), h.rva.c_str());
            continue;
        }
        if (h.action.find('!') != std::string::npos) {
            attach_handler(h, at, folder);
            continue;
        }
        if (g_used == kThunks) {
            log("%s: skipped (more than %d hooks with built-in actions)", h.name.c_str(), kThunks);
            continue;
        }
        Site& s = g_sites[g_used];
        s.hook = h;
        if (h.action == "log" || h.action.empty()) {
            s.kind = Kind::Log;
        } else if (h.action == "skip") {
            s.kind = Kind::Skip;
        } else if (h.action.compare(0, 7, "return ") == 0) {
            s.kind = Kind::Return;
            s.value = static_cast<unsigned long long>(std::strtoll(h.action.c_str() + 7, nullptr, 0));
        } else {
            log("%s: skipped (unknown action \"%s\")", h.name.c_str(), h.action.c_str());
            continue;
        }
        s.original = at;
        bool ok = attach(&s.original, pbeta_host_thunks[g_used]);
        if (ok) {
            g_used++;
        }
        log("%s: %s at %s, %s%s", h.name.c_str(), ok ? "attached" : "attach failed", h.rva.c_str(),
            h.action.empty() ? "log" : h.action.c_str(), h.pattern.empty() ? "" : " (pattern checked)");
    }
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        InitializeCriticalSection(&g_lock);
        wchar_t me[MAX_PATH * 2] = {};
        GetModuleFileNameW(self, me, ARRAYSIZE(me));
        std::wstring config = env(L"PBETA_HOST_CONFIG");
        if (config.empty()) {
            config = folder_of(me) + L"pbeta-host.toml";
        }
        std::wstring log_path = env(L"PBETA_HOST_LOG");
        if (log_path.empty()) {
            log_path = folder_of(config) + L"pbeta-host.log";
        }
        g_log = _wfopen(log_path.c_str(), L"ab");
        attach_all(config);
    } else if (reason == DLL_PROCESS_DETACH) {
        // Detours stay attached: the process is exiting.
        log("exit");
        if (g_log) {
            std::fclose(g_log);
            g_log = nullptr;
        }
    }
    return TRUE;
}
