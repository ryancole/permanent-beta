// Hook DLL for the M4 hook-repair loop (corpus/hooks/README.md).
//
// Loaded into the sample app by launcher.exe (DetourCreateProcessWithDllExW). On load it reads a hook manifest
// (design §7.1, the TOML that `pbeta repair --out` writes), attaches a logging detour to every hook whose
// locator is bound to the running build, and writes a JSON Lines trace:
//
//   {"event":"start","build":"<sha256>"}
//   {"event":"attach","hook":"price_lookup","rva":"0x1010","status":"ok"}        (or "status":"error 87")
//   {"event":"skip","hook":"log_event","reason":"build_mismatch","build":"<locator's build>"}
//   {"event":"call","hook":"price_lookup","rva":"0x1010","args":["10"],"ret":"470"}
//   {"event":"end"}
//
// A hook whose locator is still bound to another build is never attached: that's how repair leaves hooks it
// sent to review (design §7.2), and patching one would put the old RVA on whatever code is there now.
//
// Configuration comes from the environment, set by the launcher:
//   PBETA_HOOKS  manifest path    PBETA_TRACE  trace output path    PBETA_BUILD  SHA-256 of the app's .exe
//
// The detours are written against the v1 prototypes. They log arguments and results by value (never pointers,
// which differ between runs), so traces of two builds can be compared line by line.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <detours.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(linker, "/export:DetourFinishHelperProcess,@1,NONAME")

namespace {

// ---------------------------------------------------------------------------------------------------------------
// Trace output

FILE* g_trace = nullptr;
CRITICAL_SECTION g_lock;

std::string json_escape(const char* s, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20 || c >= 0x7f) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string quoted(const std::string& s) {
    return "\"" + json_escape(s.data(), s.size()) + "\"";
}

void emit(const std::string& line) {
    if (!g_trace) {
        return;
    }
    EnterCriticalSection(&g_lock);
    std::fputs(line.c_str(), g_trace);
    std::fputc('\n', g_trace);
    std::fflush(g_trace);  // a crash must not lose the calls before it
    LeaveCriticalSection(&g_lock);
}

std::string hex(unsigned long long v) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%llx", v);
    return buf;
}

std::string num(long long v) {
    return std::to_string(v);
}

std::string text(const char* s) {
    return s ? std::string(s) : std::string("(null)");
}

// One attached hook: its manifest name and RVA, for the call records.
struct Site {
    std::string hook;
    unsigned long long rva = 0;
};

void emit_call(const Site& site, const std::vector<std::string>& args, const std::string& ret) {
    std::string line = "{\"event\":\"call\",\"hook\":" + quoted(site.hook) + ",\"rva\":\"" + hex(site.rva) +
                       "\",\"args\":[";
    for (size_t i = 0; i < args.size(); i++) {
        line += (i ? "," : "") + quoted(args[i]);
    }
    line += "],\"ret\":" + quoted(ret) + "}";
    emit(line);
}

// ---------------------------------------------------------------------------------------------------------------
// Detours, against the sample app's v1 prototypes

struct Order {  // the app's layout (fields this DLL reads)
    int id;
    int count;
};

#define DECLARE_SITE(name) \
    Site g_site_##name;     \
    decltype(&Hook_##name) Real_##name = nullptr;

void Hook_log_event(const char* msg, int code);
int Hook_price_lookup(int sku);
int Hook_stock_level(int sku);
int Hook_apply_discount(int cents, int percent);
int Hook_order_add(Order* o, int sku, int qty);
int Hook_format_receipt(char* buf, int cap, const Order* o, const char* customer);
unsigned Hook_checksum(const unsigned char* data, int len);
unsigned Hook_ship_order(Order* o, const char* customer, int discount);

DECLARE_SITE(log_event)
DECLARE_SITE(price_lookup)
DECLARE_SITE(stock_level)
DECLARE_SITE(apply_discount)
DECLARE_SITE(order_add)
DECLARE_SITE(format_receipt)
DECLARE_SITE(checksum)
DECLARE_SITE(ship_order)

void Hook_log_event(const char* msg, int code) {
    Real_log_event(msg, code);
    emit_call(g_site_log_event, {text(msg), num(code)}, "");
}

int Hook_price_lookup(int sku) {
    int r = Real_price_lookup(sku);
    emit_call(g_site_price_lookup, {num(sku)}, num(r));
    return r;
}

int Hook_stock_level(int sku) {
    int r = Real_stock_level(sku);
    emit_call(g_site_stock_level, {num(sku)}, num(r));
    return r;
}

int Hook_apply_discount(int cents, int percent) {
    int r = Real_apply_discount(cents, percent);
    emit_call(g_site_apply_discount, {num(cents), num(percent)}, num(r));
    return r;
}

int Hook_order_add(Order* o, int sku, int qty) {
    std::vector<std::string> args{num(o->id), num(o->count), num(sku), num(qty)};
    int r = Real_order_add(o, sku, qty);
    emit_call(g_site_order_add, args, num(r));
    return r;
}

int Hook_format_receipt(char* buf, int cap, const Order* o, const char* customer) {
    int r = Real_format_receipt(buf, cap, o, customer);
    emit_call(g_site_format_receipt, {num(cap), num(o->id), text(customer)}, num(r) + ":" + text(buf));
    return r;
}

unsigned Hook_checksum(const unsigned char* data, int len) {
    unsigned r = Real_checksum(data, len);
    std::string bytes(reinterpret_cast<const char*>(data), len > 0 ? static_cast<size_t>(len) : 0);
    emit_call(g_site_checksum, {bytes, num(len)}, num(r));
    return r;
}

unsigned Hook_ship_order(Order* o, const char* customer, int discount) {
    std::vector<std::string> args{num(o->id), text(customer), num(discount)};
    unsigned r = Real_ship_order(o, customer, discount);
    emit_call(g_site_ship_order, args, num(r));
    return r;
}

struct Detour {
    const char* symbol;  // the manifest's `detour`
    Site* site;
    PVOID* real;
    PVOID detour;
};

#define DETOUR(name) \
    {"Hook_" #name, &g_site_##name, reinterpret_cast<PVOID*>(&Real_##name), reinterpret_cast<PVOID>(&Hook_##name)}

Detour g_detours[] = {
    DETOUR(log_event),
    DETOUR(price_lookup),
    DETOUR(stock_level),
    DETOUR(apply_discount),
    DETOUR(order_add),
    DETOUR(format_receipt),
    DETOUR(checksum),
    DETOUR(ship_order),
};

// ---------------------------------------------------------------------------------------------------------------
// Hook manifest: the TOML subset `pbeta` writes ([[hook]], [hook.target], key = "string" | integer, comments)

struct HookEntry {
    std::string name, detour, build, rva;
};

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    size_t e = s.find_last_not_of(" \t\r\n");
    return b == std::string::npos ? std::string() : s.substr(b, e - b + 1);
}

// Value of `key = value`: a basic string (with \" and \\ escapes) or a bare token up to a comment.
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

bool parse_manifest(const char* path, std::vector<HookEntry>& hooks) {
    FILE* f = std::fopen(path, "rb");
    if (!f) {
        return false;
    }
    std::string section;
    char buf[4096];
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
        if (line[0] == '[') {
            section = line == "[hook.target]" ? "target" : "other";
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos || hooks.empty()) {
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string value = toml_value(line.substr(eq + 1));
        HookEntry& h = hooks.back();
        if (section == "hook" && key == "name") {
            h.name = value;
        } else if (section == "hook" && key == "detour") {
            h.detour = value;
        } else if (section == "target" && key == "build") {
            h.build = value;
        } else if (section == "target" && key == "rva") {
            h.rva = value;
        }
    }
    std::fclose(f);
    return true;
}

std::string env(const char* name) {
    char buf[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableA(name, buf, sizeof buf);
    return n > 0 && n < sizeof buf ? std::string(buf, n) : std::string();
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return s;
}

void attach_all() {
    std::string build = lower(env("PBETA_BUILD"));
    emit("{\"event\":\"start\",\"build\":" + quoted(build) + "}");

    std::vector<HookEntry> hooks;
    std::string manifest = env("PBETA_HOOKS");
    if (manifest.empty() || !parse_manifest(manifest.c_str(), hooks)) {
        emit("{\"event\":\"error\",\"detail\":" + quoted("cannot read manifest " + manifest) + "}");
        return;
    }
    auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));

    for (const HookEntry& h : hooks) {
        auto skip = [&](const char* reason) {
            emit("{\"event\":\"skip\",\"hook\":" + quoted(h.name) + ",\"reason\":\"" + reason +
                 "\",\"build\":" + quoted(h.build) + "}");
        };
        if (build.empty() || lower(h.build) != build) {
            skip("build_mismatch");
            continue;
        }
        Detour* d = nullptr;
        for (Detour& candidate : g_detours) {
            if (h.detour == candidate.symbol) {
                d = &candidate;
            }
        }
        if (!d) {
            skip("unknown_detour");
            continue;
        }
        if (h.rva.empty()) {
            skip("no_rva");
            continue;
        }
        unsigned long long rva = std::strtoull(h.rva.c_str(), nullptr, 0);
        d->site->hook = h.name;
        d->site->rva = rva;
        *d->real = base + rva;

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        LONG err = DetourAttach(d->real, d->detour);
        if (err == NO_ERROR) {
            err = DetourTransactionCommit();
        } else {
            DetourTransactionAbort();
        }
        emit("{\"event\":\"attach\",\"hook\":" + quoted(h.name) + ",\"rva\":\"" + hex(rva) + "\",\"status\":" +
             quoted(err == NO_ERROR ? "ok" : "error " + num(err)) + "}");
    }
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    if (reason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();
        InitializeCriticalSection(&g_lock);
        std::string path = env("PBETA_TRACE");
        if (!path.empty()) {
            g_trace = std::fopen(path.c_str(), "wb");
        }
        attach_all();
    } else if (reason == DLL_PROCESS_DETACH) {
        // Detours stay attached: the process is exiting, and its code is about to go away with them.
        emit("{\"event\":\"end\"}");
        if (g_trace) {
            std::fclose(g_trace);
            g_trace = nullptr;
        }
    }
    return TRUE;
}
