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
// Record mode (below, "Record mode"), set by the caller of the launcher:
//   PBETA_RECORD  recording directory    PBETA_SPEC  record spec (`pbeta harness-spec`)
//
// The detours are written against the v1 prototypes. They log arguments and results by value (never pointers,
// which differ between runs), so traces of two builds can be compared line by line.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <bcrypt.h>
#include <detours.h>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#pragma comment(linker, "/export:DetourFinishHelperProcess,@1,NONAME")
#pragma comment(lib, "bcrypt.lib")

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

// ---------------------------------------------------------------------------------------------------------------
// Record mode (design §7.3): with PBETA_RECORD set, the DLL attaches the generic register-capturing thunk
// (record_thunk.asm) instead of the logging detours, to every hook of the record spec (PBETA_SPEC, written by
// `pbeta harness-spec`) bound to the running build. Per call it writes one JSON test case
// (permanent_beta_model::TestCase) to PBETA_RECORD/cases/<hook>/, the memory behind pointer arguments before and
// after the call to PBETA_RECORD/blobs/<sha256>, and copies the spec to PBETA_RECORD/spec.toml. Identical calls are
// recorded once, and at most `max_cases` per hook. Recordings can contain customer data: they stay local.
//
// With each call it also captures the spec's globals for the hook (`[[hook.global]]`) before and after, and the
// import calls made while the call runs ("Import calls" below).
//
// Redaction: an argument or global with `redact = true` is never captured, and neither is any import call's memory
// that overlaps a redacted argument seen so far in the run. That's best effort: an import can still be handed
// data derived from a redacted argument (a receipt formatted from a name), or a redacted value at an address no
// redacted argument pointed to. `import_memory = false` captures no import memory at all, which is the guarantee.

const char kRecorder[] = "permanent-beta-hookdll 0.2";
constexpr int kThunks = 16;
constexpr int kMaxArgs = 16;
// Import calls: patched import address table slots (the 256 import thunks in record_thunk.asm; zstd has 112 imports), stack arguments
// recorded, and bytes captured behind an argument (kImportBlock) and behind a pointer inside that (kImportInner).
// [Guess]
constexpr int kImportThunks = 256;
constexpr int kImportStackArgs = 8;
constexpr size_t kImportBlock = 512;
constexpr size_t kImportInner = 256;
constexpr size_t kMaxImportCalls = 1024;  // per case; past it the case drops its import calls

// Must match record_thunk.asm.
struct RecordFrame {
    unsigned long long gpr[4];      // rcx, rdx, r8, r9
    unsigned char xmm[4][16];       // xmm0-xmm3
    unsigned long long slot;        // which thunk
    unsigned long long entry_rsp;   // [entry_rsp] is the return address
    unsigned long long rax;         // returned
    unsigned char xmm0[16];         // returned
    void* call;                     // the pending call (RecordCall), or null when not recording it
};
static_assert(offsetof(RecordFrame, xmm) == 0x20, "record_thunk.asm F_XMM");
static_assert(offsetof(RecordFrame, slot) == 0x60, "record_thunk.asm F_SLOT");
static_assert(offsetof(RecordFrame, entry_rsp) == 0x68, "record_thunk.asm F_RSP");
static_assert(offsetof(RecordFrame, rax) == 0x70, "record_thunk.asm F_RAX");
static_assert(offsetof(RecordFrame, xmm0) == 0x78, "record_thunk.asm F_XMM0");
static_assert(offsetof(RecordFrame, call) == 0x88, "record_thunk.asm F_CALL");
static_assert(sizeof(RecordFrame) == 0x90, "record_thunk.asm FRAME_BYTES");

// One argument of the spec (`[[hook.arg]]`).
struct RecArg {
    int index = -1;
    std::string slot, capture, layout, len_slot;
    unsigned long long size = 0, max = 0;
    bool redact = false;
};

// A global to capture with each call (`[[hook.global]]`).
struct RecGlobal {
    std::string name, rva;
    unsigned long long size = 0;
    bool redact = false;
};

struct RecHook {
    std::string name, rva;
    unsigned stack_args = 0;
    std::vector<RecArg> args;
    std::vector<RecGlobal> globals;
};

// A pointer field of a layout (`[[pointer]]`), and the layout it points to ("" for bytes).
struct RecPointer {
    std::string layout, target;
    unsigned long long offset = 0;
};

struct RecSpec {
    std::string build;
    unsigned max_cases = 32;
    bool import_memory = true;
    unsigned pointer_depth = 0;
    std::vector<RecHook> hooks;
    std::vector<RecPointer> pointers;
    std::vector<std::pair<std::string, unsigned long long>> layouts;  // name, size
};

// The TOML subset `pbeta harness-spec` writes: top-level keys, [[hook]], [[hook.arg]], [[hook.global]]; other
// tables are skipped.
bool parse_spec(const char* path, RecSpec& spec) {
    FILE* f = std::fopen(path, "rb");
    if (!f) {
        return false;
    }
    std::string section = "top";
    char buf[4096];
    while (std::fgets(buf, sizeof buf, f)) {
        std::string line = trim(buf);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line == "[[hook]]") {
            spec.hooks.emplace_back();
            section = "hook";
            continue;
        }
        if (line == "[[hook.arg]]") {
            if (!spec.hooks.empty()) {
                spec.hooks.back().args.emplace_back();
                section = "arg";
            }
            continue;
        }
        if (line == "[[hook.global]]") {
            if (!spec.hooks.empty()) {
                spec.hooks.back().globals.emplace_back();
                section = "global";
            }
            continue;
        }
        if (line == "[[pointer]]") {
            spec.pointers.emplace_back();
            section = "pointer";
            continue;
        }
        if (line == "[[layout]]") {
            spec.layouts.emplace_back();
            section = "layout";
            continue;
        }
        if (line[0] == '[') {
            section = "other";
            continue;
        }
        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = trim(line.substr(0, eq));
        std::string value = toml_value(line.substr(eq + 1));
        unsigned long long n = std::strtoull(value.c_str(), nullptr, 0);
        if (section == "top") {
            if (key == "build") {
                spec.build = value;
            } else if (key == "max_cases") {
                spec.max_cases = static_cast<unsigned>(n);
            } else if (key == "import_memory") {
                spec.import_memory = value != "false";
            } else if (key == "pointer_depth") {
                spec.pointer_depth = static_cast<unsigned>(n);
            }
        } else if (section == "hook") {
            RecHook& h = spec.hooks.back();
            if (key == "name") {
                h.name = value;
            } else if (key == "rva") {
                h.rva = value;
            } else if (key == "stack_args") {
                h.stack_args = static_cast<unsigned>(n);
            }
        } else if (section == "arg") {
            RecArg& a = spec.hooks.back().args.back();
            if (key == "index") {
                a.index = static_cast<int>(n);
            } else if (key == "slot") {
                a.slot = value;
            } else if (key == "capture") {
                a.capture = value;
            } else if (key == "size") {
                a.size = n;
            } else if (key == "layout") {
                a.layout = value;
            } else if (key == "len_slot") {
                a.len_slot = value;
            } else if (key == "max") {
                a.max = n;
            } else if (key == "redact") {
                a.redact = value == "true";
            }
        } else if (section == "pointer") {
            RecPointer& p = spec.pointers.back();
            if (key == "layout") {
                p.layout = value;
            } else if (key == "offset") {
                p.offset = n;
            } else if (key == "target") {
                p.target = value;
            }
        } else if (section == "layout") {
            if (key == "name") {
                spec.layouts.back().first = value;
            } else if (key == "size") {
                spec.layouts.back().second = n;
            }
        } else if (section == "global") {
            RecGlobal& g = spec.hooks.back().globals.back();
            if (key == "name") {
                g.name = value;
            } else if (key == "rva") {
                g.rva = value;
            } else if (key == "size") {
                g.size = n;
            } else if (key == "redact") {
                g.redact = value == "true";
            }
        }
    }
    std::fclose(f);
    return true;
}

extern "C" {
void pbeta_record_thunk0();
void pbeta_record_thunk1();
void pbeta_record_thunk2();
void pbeta_record_thunk3();
void pbeta_record_thunk4();
void pbeta_record_thunk5();
void pbeta_record_thunk6();
void pbeta_record_thunk7();
void pbeta_record_thunk8();
void pbeta_record_thunk9();
void pbeta_record_thunk10();
void pbeta_record_thunk11();
void pbeta_record_thunk12();
void pbeta_record_thunk13();
void pbeta_record_thunk14();
void pbeta_record_thunk15();
}

void (*const g_thunks[kThunks])() = {
    pbeta_record_thunk0,  pbeta_record_thunk1,  pbeta_record_thunk2,  pbeta_record_thunk3,
    pbeta_record_thunk4,  pbeta_record_thunk5,  pbeta_record_thunk6,  pbeta_record_thunk7,
    pbeta_record_thunk8,  pbeta_record_thunk9,  pbeta_record_thunk10, pbeta_record_thunk11,
    pbeta_record_thunk12, pbeta_record_thunk13, pbeta_record_thunk14, pbeta_record_thunk15,
};

struct RecSite {
    RecHook hook;
    unsigned long long rva = 0;
    PVOID real = nullptr;  // the Detours trampoline
    unsigned cases = 0;
    std::vector<std::string> seen;  // keys of the cases written, to drop identical calls
};

RecSite g_rec_sites[kThunks];
std::string g_rec_dir;
std::string g_rec_build;
unsigned g_rec_max = 32;
unsigned long long g_image_base = 0;
unsigned long long g_image_size = 0;  // SizeOfImage: replay tells pointers into the image from other values

// Copies n bytes, or fails on memory that can't be read. No C++ objects here: __try needs none to unwind.
bool safe_copy(void* dst, const void* src, size_t n) {
    __try {
        std::memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Length of a NUL-terminated string, counting the NUL, at most max bytes; 0 if unreadable.
size_t safe_strlen(const char* s, size_t max) {
    __try {
        for (size_t i = 0; i < max; i++) {
            if (s[i] == '\0') {
                return i + 1;
            }
        }
        return max;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

std::string hex_bytes(const unsigned char* p, size_t n) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; i++) {
        out += digits[p[i] >> 4];
        out += digits[p[i] & 15];
    }
    return out;
}

std::string sha256_hex(const std::vector<unsigned char>& data) {
    unsigned char digest[32] = {};
    BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, const_cast<PUCHAR>(data.data()),
               static_cast<ULONG>(data.size()), digest, sizeof digest);
    return hex_bytes(digest, sizeof digest);
}

// The 64-bit value of an argument slot at entry (`rcx`, `xmm1`, `stack+0x28`).
bool slot_value(const RecordFrame* f, const std::string& slot, unsigned long long& out) {
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

struct PendingRegion {
    int arg = -1;
    unsigned long long address = 0;
    std::string kind, layout;
    std::vector<unsigned char> before, after;
};

struct PendingGlobal {
    const RecGlobal* global = nullptr;
    std::vector<unsigned char> before;
};

// ---------------------------------------------------------------------------------------------------------------
// Import calls
//
// In record mode every named import of the app's own import address table is pointed at an import thunk
// (record_thunk.asm), which calls the real function. A call made while a recorded call runs on the same thread
// (nested hooked calls included) is recorded into each of them: the argument registers and kImportStackArgs stack
// arguments, what it returned, and memory: for each argument that points to readable memory, up to kImportBlock
// bytes from it before and after the call; inside those blocks, for each 8-byte word that points to readable
// memory, up to kImportInner bytes before the call (the strings a va_list points to). Only the app's slots are
// patched: this DLL's own calls into the CRT go through its own import table.
//
// A case says `imports_recorded` only when every import of the app was patched (none by ordinal, no more than
// kImportThunks): otherwise its import calls might be incomplete, and a replay mustn't stand in for any.
// Nor when the call made more than kMaxImportCalls import calls: the case keeps none of them, so it stays small and
// a replay that reaches an import is inconclusive.

struct Snap {
    unsigned long long address = 0;
    std::vector<unsigned char> before, after;
    bool outer = false;  // an argument's block: captured after the call too
};

struct ImportRecord {
    std::string name;
    unsigned long long gpr[4] = {};
    unsigned char xmm[4][16] = {};
    unsigned long long stack[kImportStackArgs] = {};
    unsigned long long rax = 0;
    unsigned char xmm0[16] = {};
    std::vector<Snap> memory;
};

struct RecordCall {
    RecSite* site = nullptr;
    unsigned long long gpr[4] = {};
    unsigned char xmm[4][16] = {};
    std::vector<unsigned long long> stack;
    std::vector<PendingRegion> regions;
    std::vector<PendingGlobal> globals;
    std::vector<ImportRecord> imports;
    bool imports_overflow = false;  // more than kMaxImportCalls: imports dropped
};

struct ImpSite {
    std::string name;  // dll!name, the DLL lowercased
    void* real = nullptr;
};

ImpSite g_imp_sites[kImportThunks];
bool g_imports_complete = false;
bool g_import_memory = true;
// The recorded calls running on this thread, innermost last.
thread_local std::vector<RecordCall*> t_active;

// Up to max bytes from address, stopping at the first page that can't be read.
std::vector<unsigned char> readable_prefix(unsigned long long address, size_t max) {
    std::vector<unsigned char> out;
    if (address < 0x10000) {
        return out;
    }
    while (out.size() < max) {
        unsigned long long at = address + out.size();
        size_t in_page = static_cast<size_t>(0x1000 - (at & 0xfff));
        size_t n = in_page < max - out.size() ? in_page : max - out.size();
        size_t old = out.size();
        out.resize(old + n);
        if (!safe_copy(out.data() + old, reinterpret_cast<const void*>(at), n)) {
            out.resize(old);
            break;
        }
    }
    return out;
}

// Whether [address, address + n) overlaps a redacted argument of any recorded call so far.
// Every redacted argument's memory seen so far in the run: a pointer left on the stack by an earlier call can
// still lead an import's capture to it.
std::vector<std::pair<unsigned long long, unsigned long long>> g_redacted;

bool overlaps_redacted(unsigned long long address, size_t n) {
    EnterCriticalSection(&g_lock);
    bool hit = false;
    for (const auto& range : g_redacted) {
        hit = hit || (address < range.second && address + n > range.first);
    }
    LeaveCriticalSection(&g_lock);
    return hit;
}

void snap_add(std::vector<Snap>& memory, unsigned long long address, size_t max, bool outer) {
    for (const Snap& s : memory) {
        if (s.address == address) {
            return;
        }
    }
    Snap s;
    s.address = address;
    s.outer = outer;
    s.before = readable_prefix(address, max);
    if (!s.before.empty() && !overlaps_redacted(address, s.before.size())) {
        memory.push_back(std::move(s));
    }
}

std::string write_blob(const std::vector<unsigned char>& data) {
    std::string digest = sha256_hex(data);
    std::string path = g_rec_dir + "\\blobs\\" + digest;
    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (FILE* f = std::fopen(path.c_str(), "wb")) {
            if (!data.empty()) {
                std::fwrite(data.data(), 1, data.size(), f);
            }
            std::fclose(f);
        }
    }
    return "sha256:" + digest;
}

std::string word(unsigned long long v) {
    return quoted(hex(v));
}

std::string entry_json(const unsigned long long gpr[4], const unsigned char xmm[4][16],
                       const unsigned long long* stack, size_t stack_n) {
    std::string out = "{\"rcx\":" + word(gpr[0]) + ",\"rdx\":" + word(gpr[1]) + ",\"r8\":" + word(gpr[2]) +
                      ",\"r9\":" + word(gpr[3]) + ",\"xmm\":[";
    for (int i = 0; i < 4; i++) {
        out += (i ? "," : "") + quoted(hex_bytes(xmm[i], 16));
    }
    out += "],\"stack\":[";
    for (size_t i = 0; i < stack_n; i++) {
        out += (i ? "," : "") + word(stack[i]);
    }
    return out + "]}";
}

std::string import_json(const ImportRecord& r) {
    std::string out = "{\"import\":" + quoted(r.name) + ",\"entry\":" +
                      entry_json(r.gpr, r.xmm, r.stack, kImportStackArgs) + ",\"observed\":{\"rax\":" +
                      word(r.rax) + ",\"xmm0\":" + quoted(hex_bytes(r.xmm0, 16)) + "},\"memory\":[";
    for (size_t i = 0; i < r.memory.size(); i++) {
        const Snap& s = r.memory[i];
        out += std::string(i ? "," : "") + "{\"address\":" + word(s.address) + ",\"before\":" +
               quoted(write_blob(s.before)) + (s.outer ? ",\"after\":" + quoted(write_blob(s.after)) : "") + "}";
    }
    return out + "]}";
}

// ---------------------------------------------------------------------------------------------------------------
// Pointees (design §7.3, the spec's `pointer_depth` and `[[pointer]]` fields)
//
// Real code keeps its state behind pointers: zlib's z_stream points to its state, which points to the window.
// Pointers are followed by type, never by guessing from bytes (an output buffer's stale bytes look like pointers):
// only the pointer fields the spec lists for a captured struct's layout. A field pointing to a struct with a layout
// captures that struct (with its layout, so replay can translate it) and is followed further, pointer_depth levels
// in all; a field pointing to bytes captures the whole heap block when it's a process-heap block's start (up to
// kPointeeHeapMax; also when it's larger than the struct, an array), otherwise up to kPointeeBlock readable bytes
// (a stack buffer, a pointer into a block; behind a pointer into the caller's stack too), and isn't followed.
// A field can be listed more than once with different target structs (`pbeta harness-spec --pointer-alias`: zlib's
// z_stream.state is an internal_state in deflate, an inflate_state in inflate): a heap block is taken as a struct
// only when it's exactly that size (larger is captured as bytes, like an array; smaller isn't that struct);
// elsewhere the first listed wins.
// Structs are followed through every level first, buffers captured after, so a buffer never swallows a struct. Pointers into the image or the recorder's own stack frames aren't followed. A region never overlaps an
// argument's region or another pointee (a bytes region is cut short where one begins; a struct that would overlap
// isn't captured), within kPointeeCaseMax bytes per case. Memory overlapping a redacted argument is never
// captured. A pointee unreadable after the call (freed) is left out of the case: a replay that touches it is
// inconclusive.

constexpr size_t kPointeeBlock = 64 * 1024;      // behind a byte pointer that isn't a heap block's start [Guess]
constexpr size_t kPointeeHeapMax = 1024 * 1024;  // of one heap block [Guess]: zstd's stream buffers are ~260 KiB
constexpr size_t kPointeeCaseMax = 4 << 20;      // per case [Guess]
unsigned g_pointer_depth = 0;
std::vector<RecPointer> g_pointers;
std::vector<std::pair<std::string, unsigned long long>> g_layout_sizes;

unsigned long long layout_size(const std::string& name) {
    for (const auto& l : g_layout_sizes) {
        if (l.first == name) {
            return l.second;
        }
    }
    return 0;
}

// The size of the process-heap block starting at p, or 0 if p isn't one.
size_t heap_block_size(unsigned long long p) {
    HANDLE heap = GetProcessHeap();
    __try {
        if (!HeapValidate(heap, 0, reinterpret_cast<LPCVOID>(p))) {
            return 0;
        }
        SIZE_T n = HeapSize(heap, 0, reinterpret_cast<LPCVOID>(p));
        return n == static_cast<SIZE_T>(-1) ? 0 : static_cast<size_t>(n);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// The busy process-heap block holding p (its start or anywhere inside it): {start, size}, or {0, 0}. Walks the
// whole heap under its lock, allocating nothing; only `array` arguments pay for it.
std::pair<unsigned long long, size_t> enclosing_heap_block(unsigned long long p) {
    HANDLE heap = GetProcessHeap();
    if (!HeapLock(heap)) {
        return {0, 0};
    }
    std::pair<unsigned long long, size_t> found{0, 0};
    PROCESS_HEAP_ENTRY e{};
    while (HeapWalk(heap, &e)) {
        unsigned long long start = reinterpret_cast<unsigned long long>(e.lpData);
        if ((e.wFlags & PROCESS_HEAP_ENTRY_BUSY) && p >= start && p - start < e.cbData) {
            found = {start, static_cast<size_t>(e.cbData)};
            break;
        }
    }
    HeapUnlock(heap);
    return found;
}

void capture_pointees(RecordCall* call, const RecordFrame* f) {
    if (g_pointer_depth == 0 || g_pointers.empty()) {
        return;
    }
    ULONG_PTR stack_low = 0, stack_high = 0;
    GetCurrentThreadStackLimits(&stack_low, &stack_high);
    // Captured intervals, [start, end): the arguments' regions, then every pointee.
    std::vector<std::pair<unsigned long long, unsigned long long>> taken;
    auto inside = [&](unsigned long long p) {
        for (const auto& t : taken) {
            if (p >= t.first && p < t.second) {
                return true;
            }
        }
        return false;
    };
    // Where the next captured interval at or after p begins.
    auto limit_after = [&](unsigned long long p) {
        unsigned long long limit = ~0ull;
        for (const auto& t : taken) {
            if (t.first > p && t.first < limit) {
                limit = t.first;
            }
        }
        return limit;
    };
    size_t total = 0;
    auto add = [&](int arg, unsigned long long at, std::vector<unsigned char> bytes, const std::string& layout) {
        total += bytes.size();
        taken.emplace_back(at, at + bytes.size());
        PendingRegion r;
        r.arg = arg;
        r.address = at;
        r.kind = "pointee";
        r.layout = layout;
        r.before = std::move(bytes);
        call->regions.push_back(std::move(r));
        return call->regions.size() - 1;
    };
    std::vector<size_t> frontier;  // regions (indices into call->regions) with a layout, to follow
    for (size_t i = 0; i < call->regions.size(); i++) {
        const PendingRegion& r = call->regions[i];
        taken.emplace_back(r.address, r.address + r.before.size());
        if (!r.layout.empty()) {
            frontier.push_back(i);
        }
    }
    // Byte buffers found on the way, captured after every struct so a buffer never swallows one.
    struct Bytes {
        int arg;
        unsigned long long p;
        size_t block;  // the heap block's size when p starts one, else 0
    };
    std::vector<Bytes> buffers;

    // 1. Structs, by type, pointer_depth levels.
    for (unsigned depth = 0; depth < g_pointer_depth && !frontier.empty(); depth++) {
        std::vector<size_t> next;
        for (size_t index : frontier) {
            // Copied: add() may move the region.
            const PendingRegion from = call->regions[index];
            for (const RecPointer& field : g_pointers) {
                if (field.layout != from.layout || field.offset + 8 > from.before.size()) {
                    continue;
                }
                unsigned long long p = 0;
                std::memcpy(&p, from.before.data() + field.offset, 8);
                if (p < 0x10000 || p > 0x7fffffffffffull || (p >= g_image_base && p < g_image_base + g_image_size) ||
                    (p >= stack_low && p < f->entry_rsp) || inside(p)) {
                    continue;  // null, not a user address, the image, the recorder's own frames, or captured
                }
                size_t block = heap_block_size(p);
                unsigned long long typed = field.target.empty() ? 0 : layout_size(field.target);
                if (typed == 0 || (block != 0 && block > typed)) {
                    buffers.push_back({from.arg, p, block});  // bytes, an array of structs, or another type
                    continue;
                }
                if (block != 0 && block < typed) {
                    continue;  // a heap block smaller than the struct isn't one (an aliased field's other type)
                }
                if (limit_after(p) - p < typed || total + typed > kPointeeCaseMax) {
                    continue;  // would overlap captured memory, or over the budget
                }
                std::vector<unsigned char> got = readable_prefix(p, static_cast<size_t>(typed));
                if (got.size() != typed || overlaps_redacted(p, got.size())) {
                    continue;
                }
                next.push_back(add(from.arg, p, std::move(got), field.target));
            }
        }
        frontier = std::move(next);
    }

    // 2. Byte buffers: whole heap blocks first (their size is known), then the whole heap block a pointer points
    // into the middle of (found by walking the heap: code reads behind such a pointer, zlib's updatewindow copies
    // from next_out - copy; and nothing past the block, which is the heap's own bookkeeping and free space, rewritten
    // by any malloc during the call), then kPointeeBlock around a pointer into the caller's stack or from any other
    // pointer (a block over kPointeeHeapMax, not the process heap), each cut short where captured memory begins.
    std::stable_sort(buffers.begin(), buffers.end(), [](const Bytes& x, const Bytes& y) {
        return (x.block != 0) > (y.block != 0);
    });
    for (const Bytes& want : buffers) {
        unsigned long long p = want.p;
        // A pointer one past the end of a heap block (C allows it: zlib's next_out at the end of its full output
        // buffer, which updatewindow copies from backwards) also captures that block.
        if (!inside(p - 1)) {
            auto behind = enclosing_heap_block(p - 1);
            if (behind.second != 0 && behind.first + behind.second == p && behind.second <= kPointeeHeapMax &&
                !inside(behind.first) && limit_after(behind.first) >= p && total + behind.second <= kPointeeCaseMax) {
                std::vector<unsigned char> got = readable_prefix(behind.first, behind.second);
                if (got.size() == behind.second && !overlaps_redacted(behind.first, got.size())) {
                    add(want.arg, behind.first, std::move(got), "");
                }
            }
        }
        if (inside(p)) {
            continue;
        }
        unsigned long long lo = p;
        unsigned long long hi;
        if (want.block) {
            hi = p + (want.block < kPointeeHeapMax ? want.block : kPointeeHeapMax);
        } else if (p >= f->entry_rsp && p < stack_high) {
            lo = p - f->entry_rsp < kPointeeBlock ? f->entry_rsp : p - kPointeeBlock;
            for (const auto& t : taken) {
                if (t.second <= p && t.second > lo) {
                    lo = t.second;
                }
            }
            hi = p + kPointeeBlock < stack_high ? p + kPointeeBlock : stack_high;
        } else if (auto block = enclosing_heap_block(p); block.second != 0 && block.second <= kPointeeHeapMax) {
            lo = block.first;
            for (const auto& t : taken) {
                if (t.second <= p && t.second > lo) {
                    lo = t.second;
                }
            }
            hi = block.first + block.second;
        } else if (block.second != 0) {
            // A block over kPointeeHeapMax: kPointeeBlock from the pointer, never past the block's end.
            unsigned long long end = block.first + block.second;
            hi = end - p < kPointeeBlock ? end : p + kPointeeBlock;
        } else {
            hi = p + kPointeeBlock;
        }
        unsigned long long limit = limit_after(p);
        if (hi > limit) {
            hi = limit;
        }
        if (total + (hi - lo) > kPointeeCaseMax) {
            return;
        }
        // From the pointer forward first: what's behind it on the stack is only added if readable too.
        std::vector<unsigned char> got = readable_prefix(lo, static_cast<size_t>(hi - lo));
        if (got.size() <= p - lo || overlaps_redacted(lo, got.size())) {
            continue;
        }
        add(want.arg, lo, std::move(got), "");
    }
}

void finish_case(RecordCall* call, const RecordFrame* f) {
    RecSite& site = *call->site;
    // Everything but the id, for spotting identical calls.
    std::string body = "\"build\":" + quoted(g_rec_build) + ",\"rva\":" + word(site.rva) + ",\"recorder\":" +
                       quoted(kRecorder) + ",\"abi\":\"win64\",\"image_base\":" + word(g_image_base) +
                       ",\"image_size\":" + word(g_image_size) +
                       ",\"entry\":{\"rcx\":" + word(call->gpr[0]) + ",\"rdx\":" + word(call->gpr[1]) +
                       ",\"r8\":" + word(call->gpr[2]) + ",\"r9\":" + word(call->gpr[3]) + ",\"xmm\":[";
    for (int i = 0; i < 4; i++) {
        body += (i ? "," : "") + quoted(hex_bytes(call->xmm[i], 16));
    }
    body += "],\"stack\":[";
    for (size_t i = 0; i < call->stack.size(); i++) {
        body += (i ? "," : "") + word(call->stack[i]);
    }
    body += "]},\"regions\":[";
    bool first = true;
    for (PendingRegion& r : call->regions) {
        r.after.resize(r.before.size());
        if (!r.before.empty() &&
            !safe_copy(r.after.data(), reinterpret_cast<const void*>(r.address), r.after.size())) {
            if (r.kind == "pointee") {
                continue;  // freed during the call: left out, so a replay that touches it is inconclusive
            }
            return;  // an argument's memory freed during the call: the case can't say what was written
        }
        body += std::string(first ? "" : ",") + "{\"arg\":" + num(r.arg) + ",\"address\":" + word(r.address) +
                ",\"size\":" + num(static_cast<long long>(r.before.size())) + ",\"kind\":" + quoted(r.kind) +
                (r.layout.empty() ? "" : ",\"layout\":" + quoted(r.layout)) + ",\"before\":" +
                quoted(write_blob(r.before)) + ",\"after\":" + quoted(write_blob(r.after)) + "}";
        first = false;
    }
    body += "],\"globals\":[";
    first = true;
    for (const PendingGlobal& g : call->globals) {
        std::vector<unsigned char> after(g.before.size());
        unsigned long long address = g_image_base + std::strtoull(g.global->rva.c_str(), nullptr, 0);
        if (!safe_copy(after.data(), reinterpret_cast<const void*>(address), after.size())) {
            return;
        }
        body += std::string(first ? "" : ",") + "{\"name\":" + quoted(g.global->name) + ",\"rva\":" +
                quoted(g.global->rva) + ",\"size\":" + num(static_cast<long long>(g.before.size())) +
                ",\"before\":" + quoted(write_blob(g.before)) + ",\"after\":" + quoted(write_blob(after)) + "}";
        first = false;
    }
    body += std::string("],\"imports_recorded\":") + (g_imports_complete && !call->imports_overflow ? "true" : "false") +
            ",\"imports\":[";
    for (size_t i = 0; i < call->imports.size(); i++) {
        body += (i ? "," : "") + import_json(call->imports[i]);
    }
    body += "],\"observed\":{\"rax\":" + word(f->rax) + ",\"xmm0\":" + quoted(hex_bytes(f->xmm0, 16)) + "}";

    EnterCriticalSection(&g_lock);
    bool seen = false;
    for (const std::string& k : site.seen) {
        seen = seen || k == body;
    }
    if (!seen && site.cases < g_rec_max) {
        site.seen.push_back(body);
        site.cases++;
        char id[32];
        std::snprintf(id, sizeof id, "%04u", site.cases);
        std::string test_id = site.hook.name + "-" + id;
        std::string path = g_rec_dir + "\\cases\\" + site.hook.name + "\\" + test_id + ".json";
        if (FILE* out = std::fopen(path.c_str(), "wb")) {
            std::string json = "{\"test_id\":" + quoted(test_id) + ",\"hook\":" + quoted(site.hook.name) + "," +
                               body + "}\n";
            std::fputs(json.c_str(), out);
            std::fclose(out);
        }
    }
    LeaveCriticalSection(&g_lock);
}

}  // namespace

// Called by record_thunk.asm before the original: capture the entry state and the arguments' memory. Returns the
// original function.
extern "C" void* pbeta_record_before(RecordFrame* f) {
    RecSite& site = g_rec_sites[f->slot % kThunks];
    f->call = nullptr;
    EnterCriticalSection(&g_lock);
    bool full = site.cases >= g_rec_max;
    LeaveCriticalSection(&g_lock);
    if (full) {
        return site.real;
    }
    auto* call = new RecordCall;
    call->site = &site;
    std::memcpy(call->gpr, f->gpr, sizeof call->gpr);
    std::memcpy(call->xmm, f->xmm, sizeof call->xmm);
    for (unsigned i = 0; i < site.hook.stack_args && i < 8; i++) {
        unsigned long long v = 0;
        safe_copy(&v, reinterpret_cast<const void*>(f->entry_rsp + 0x28 + 8 * i), 8);
        call->stack.push_back(v);
    }
    for (const RecArg& a : site.hook.args) {
        unsigned long long address = 0;
        if (a.capture.empty() || a.capture == "none" || !slot_value(f, a.slot, address) || address == 0) {
            continue;
        }
        size_t n = 0;
        unsigned long long at = address;  // where the captured region starts
        if (a.capture == "fixed") {
            n = static_cast<size_t>(a.size);
        } else if (a.capture == "array") {
            // A scalar that may be an element of an array (design §7.3): the whole heap block holding it, from
            // its start, unless the block is over kPointeeHeapMax, overlaps redacted memory, or overlaps another
            // argument's region without lying inside it; then its own bytes, as `fixed`.
            n = static_cast<size_t>(a.size);
            auto block = enclosing_heap_block(address);
            // In a block over kPointeeHeapMax (zstd's workspace, megabytes), kPointeeBlock from the element on,
            // within the block: arrays are indexed forward from the pointer.
            if (block.second > kPointeeHeapMax) {
                unsigned long long end = block.first + block.second;
                block = {address, static_cast<size_t>(end - address < kPointeeBlock ? end - address : kPointeeBlock)};
            }
            if (block.second >= n && block.second <= kPointeeHeapMax && !overlaps_redacted(block.first, block.second)) {
                unsigned long long lo = block.first, hi = block.first + block.second;
                bool inside_one = false, typed_overlap = false;
                for (const PendingRegion& r : call->regions) {
                    unsigned long long rlo = r.address, rhi = r.address + r.before.size();
                    if (rlo <= lo && hi <= rhi) {
                        inside_one = true;
                    } else if (lo < rhi && rlo < hi && !r.layout.empty()) {
                        typed_overlap = true;  // a struct's bytes can't be merged: replay translates them
                    }
                }
                if (inside_one && !a.redact) {
                    continue;  // another argument's region already holds it (inflate_table's pointers)
                }
                if (!typed_overlap && !a.redact) {
                    // Untyped regions this one overlaps or holds (another array of the same workspace, a buffer
                    // inside the same context: zstd's count and normalizedCounter, DTable and the literals
                    // buffer) are merged into one region covering them all.
                    for (const PendingRegion& r : call->regions) {
                        unsigned long long rlo = r.address, rhi = r.address + r.before.size();
                        if (lo < rhi && rlo < hi) {
                            lo = rlo < lo ? rlo : lo;
                            hi = rhi > hi ? rhi : hi;
                        }
                    }
                    if (hi - lo <= kPointeeHeapMax && !overlaps_redacted(lo, static_cast<size_t>(hi - lo))) {
                        call->regions.erase(
                            std::remove_if(call->regions.begin(), call->regions.end(),
                                           [&](const PendingRegion& r) {
                                               return r.address < hi && lo < r.address + r.before.size();
                                           }),
                            call->regions.end());
                        at = lo;
                        n = static_cast<size_t>(hi - lo);
                    }
                } else if (!typed_overlap) {
                    at = lo;
                    n = block.second;
                }
            }
        } else if (a.capture == "cstring") {
            n = safe_strlen(reinterpret_cast<const char*>(address), static_cast<size_t>(a.max ? a.max : 4096));
        } else if (a.capture == "sized") {
            unsigned long long len = 0;
            if (slot_value(f, a.len_slot, len)) {
                long long signed_len = static_cast<int>(len & 0xffffffffu);  // the length is an `int`-sized value
                n = signed_len > 0 ? static_cast<size_t>(signed_len) : 0;
                if (a.max && n > a.max) {
                    n = static_cast<size_t>(a.max);
                }
            }
        }
        if (a.redact) {
            if (n) {
                EnterCriticalSection(&g_lock);
                g_redacted.emplace_back(at, at + n);
                LeaveCriticalSection(&g_lock);
            }
            continue;  // never captured
        }
        PendingRegion r;
        r.arg = a.index;
        r.address = at;
        r.kind = a.capture;
        r.layout = a.layout;
        r.before.resize(n);
        if (n && !safe_copy(r.before.data(), reinterpret_cast<const void*>(at), n)) {
            continue;  // unreadable: not captured, so a replay that reads it is inconclusive
        }
        call->regions.push_back(std::move(r));
    }
    for (const RecGlobal& g : site.hook.globals) {
        if (g.redact) {
            continue;  // never captured
        }
        PendingGlobal pg;
        pg.global = &g;
        pg.before.resize(static_cast<size_t>(g.size));
        unsigned long long address = g_image_base + std::strtoull(g.rva.c_str(), nullptr, 0);
        if (!safe_copy(pg.before.data(), reinterpret_cast<const void*>(address), pg.before.size())) {
            continue;  // not captured: a replay that reads it is inconclusive
        }
        call->globals.push_back(std::move(pg));
    }
    capture_pointees(call, f);
    f->call = call;
    t_active.push_back(call);
    return site.real;
}

// Called by record_thunk.asm after the original returned: the memory again, then the test case.
extern "C" void pbeta_record_after(RecordFrame* f) {
    auto* call = static_cast<RecordCall*>(f->call);
    if (!call) {
        return;
    }
    if (!t_active.empty() && t_active.back() == call) {
        t_active.pop_back();
    }
    finish_case(call, f);
    delete call;
}

// Called by record_thunk.asm before an import: captures the call if a recorded call is running on this thread.
// Returns the real function.
extern "C" void* pbeta_import_before(RecordFrame* f) {
    ImpSite& site = g_imp_sites[f->slot % kImportThunks];
    f->call = nullptr;
    bool wanted = false;
    for (const RecordCall* call : t_active) {
        wanted = wanted || !call->imports_overflow;
    }
    if (!wanted) {
        return site.real;
    }
    auto* r = new ImportRecord;
    r->name = site.name;
    std::memcpy(r->gpr, f->gpr, sizeof r->gpr);
    std::memcpy(r->xmm, f->xmm, sizeof r->xmm);
    for (int i = 0; i < kImportStackArgs; i++) {
        safe_copy(&r->stack[i], reinterpret_cast<const void*>(f->entry_rsp + 0x28 + 8 * i), 8);
    }
    std::vector<unsigned long long> args(r->gpr, r->gpr + 4);
    args.insert(args.end(), r->stack, r->stack + kImportStackArgs);
    for (unsigned long long a : g_import_memory ? args : std::vector<unsigned long long>()) {
        snap_add(r->memory, a, kImportBlock, true);
    }
    size_t outer = r->memory.size();
    for (size_t i = 0; i < outer; i++) {
        const std::vector<unsigned char> block = r->memory[i].before;
        for (size_t off = 0; off + 8 <= block.size(); off += 8) {
            unsigned long long p = 0;
            std::memcpy(&p, block.data() + off, 8);
            snap_add(r->memory, p, kImportInner, false);
        }
    }
    f->call = r;
    return site.real;
}

// Called by record_thunk.asm after the import returned: the blocks again, then the call into every recorded call
// running on this thread.
extern "C" void pbeta_import_after(RecordFrame* f) {
    auto* r = static_cast<ImportRecord*>(f->call);
    if (!r) {
        return;
    }
    r->rax = f->rax;
    std::memcpy(r->xmm0, f->xmm0, sizeof r->xmm0);
    for (Snap& s : r->memory) {
        if (s.outer) {
            s.after = readable_prefix(s.address, s.before.size());
            s.after.resize(s.before.size());
        }
    }
    for (RecordCall* call : t_active) {
        if (call->imports_overflow) {
            continue;
        }
        if (call->imports.size() >= kMaxImportCalls) {
            call->imports_overflow = true;
            std::vector<ImportRecord>().swap(call->imports);
            continue;
        }
        call->imports.push_back(*r);
    }
    delete r;
}

namespace {

extern "C" void* const pbeta_import_thunks[kImportThunks];

// Points every named import of the app's import address table at an import thunk. Sets g_imports_complete when
// none was left out.
void patch_imports() {
    auto base = reinterpret_cast<unsigned char*>(GetModuleHandleW(nullptr));
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) {
        g_imports_complete = true;
        return;
    }
    bool complete = true;
    int used = 0;
    for (auto d = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress); d->Name; d++) {
        std::string dll = lower(reinterpret_cast<const char*>(base + d->Name));
        if (dll.find("hookdll") != std::string::npos) {
            continue;  // this DLL, added to the import table by the launcher
        }
        DWORD names_rva = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
        auto names = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + names_rva);
        auto slots = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + d->FirstThunk);
        for (; names->u1.AddressOfData; names++, slots++) {
            if (IMAGE_SNAP_BY_ORDINAL64(names->u1.Ordinal) || used == kImportThunks) {
                complete = false;
                continue;
            }
            auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            ImpSite& site = g_imp_sites[used];
            site.name = dll + "!" + reinterpret_cast<const char*>(by_name->Name);
            site.real = reinterpret_cast<void*>(slots->u1.Function);
            DWORD old = 0;
            if (!VirtualProtect(&slots->u1.Function, 8, PAGE_READWRITE, &old)) {
                complete = false;
                continue;
            }
            slots->u1.Function = reinterpret_cast<ULONGLONG>(pbeta_import_thunks[used]);
            VirtualProtect(&slots->u1.Function, 8, old, &old);
            used++;
        }
    }
    g_imports_complete = complete;
    emit("{\"event\":\"imports\",\"patched\":" + num(used) + ",\"complete\":" +
         (complete ? "true" : "false") + "}");
}

void record_all(const std::string& build) {
    emit("{\"event\":\"start\",\"build\":" + quoted(build) + "}");
    RecSpec spec;
    std::string path = env("PBETA_SPEC");
    if (path.empty() || !parse_spec(path.c_str(), spec)) {
        emit("{\"event\":\"error\",\"detail\":" + quoted("cannot read record spec " + path) + "}");
        return;
    }
    if (lower(spec.build) != build) {
        emit("{\"event\":\"error\",\"detail\":" + quoted("record spec is for build " + spec.build) + "}");
        return;
    }
    g_rec_build = build;
    g_rec_max = spec.max_cases;
    g_import_memory = spec.import_memory;
    g_pointer_depth = spec.pointer_depth;
    g_pointers = spec.pointers;
    g_layout_sizes = spec.layouts;
    g_image_base = reinterpret_cast<unsigned long long>(GetModuleHandleW(nullptr));
    {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(g_image_base);
        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(g_image_base + dos->e_lfanew);
        g_image_size = nt->OptionalHeader.SizeOfImage;
    }
    CreateDirectoryA(g_rec_dir.c_str(), nullptr);
    CreateDirectoryA((g_rec_dir + "\\cases").c_str(), nullptr);
    CreateDirectoryA((g_rec_dir + "\\blobs").c_str(), nullptr);
    CopyFileA(path.c_str(), (g_rec_dir + "\\spec.toml").c_str(), FALSE);
    patch_imports();

    int used = 0;
    for (const RecHook& h : spec.hooks) {
        if (used == kThunks) {
            emit("{\"event\":\"skip\",\"hook\":" + quoted(h.name) + ",\"reason\":\"no_thunk_left\"}");
            continue;
        }
        RecSite& site = g_rec_sites[used];
        site.hook = h;
        site.rva = std::strtoull(h.rva.c_str(), nullptr, 0);
        site.real = reinterpret_cast<unsigned char*>(g_image_base) + site.rva;
        CreateDirectoryA((g_rec_dir + "\\cases\\" + h.name).c_str(), nullptr);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        LONG err = DetourAttach(&site.real, reinterpret_cast<PVOID>(g_thunks[used]));
        if (err == NO_ERROR) {
            err = DetourTransactionCommit();
        } else {
            DetourTransactionAbort();
        }
        emit("{\"event\":\"attach\",\"hook\":" + quoted(h.name) + ",\"rva\":\"" + hex(site.rva) + "\",\"status\":" +
             quoted(err == NO_ERROR ? "ok" : "error " + num(err)) + "}");
        used++;
    }
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
        g_rec_dir = env("PBETA_RECORD");
        if (g_rec_dir.empty()) {
            attach_all();
        } else {
            record_all(lower(env("PBETA_BUILD")));
        }
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
