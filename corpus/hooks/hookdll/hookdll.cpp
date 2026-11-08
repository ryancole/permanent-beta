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

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
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

const char kRecorder[] = "permanent-beta-hookdll 0.1";
constexpr int kThunks = 16;
constexpr int kMaxArgs = 16;

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
};

struct RecHook {
    std::string name, rva;
    unsigned stack_args = 0;
    std::vector<RecArg> args;
};

struct RecSpec {
    std::string build;
    unsigned max_cases = 32;
    std::vector<RecHook> hooks;
};

// The TOML subset `pbeta harness-spec` writes: top-level keys, [[hook]], [[hook.arg]]; other tables are skipped.
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

struct RecordCall {
    RecSite* site = nullptr;
    unsigned long long gpr[4] = {};
    unsigned char xmm[4][16] = {};
    std::vector<unsigned long long> stack;
    std::vector<PendingRegion> regions;
};

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

void finish_case(RecordCall* call, const RecordFrame* f) {
    RecSite& site = *call->site;
    // Everything but the id, for spotting identical calls.
    std::string body = "\"build\":" + quoted(g_rec_build) + ",\"rva\":" + word(site.rva) + ",\"recorder\":" +
                       quoted(kRecorder) + ",\"abi\":\"win64\",\"image_base\":" + word(g_image_base) +
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
            return;  // freed during the call: the case can't say what was written
        }
        body += std::string(first ? "" : ",") + "{\"arg\":" + num(r.arg) + ",\"address\":" + word(r.address) +
                ",\"size\":" + num(static_cast<long long>(r.before.size())) + ",\"kind\":" + quoted(r.kind) +
                (r.layout.empty() ? "" : ",\"layout\":" + quoted(r.layout)) + ",\"before\":" +
                quoted(write_blob(r.before)) + ",\"after\":" + quoted(write_blob(r.after)) + "}";
        first = false;
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
        if (a.capture == "fixed") {
            n = static_cast<size_t>(a.size);
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
        PendingRegion r;
        r.arg = a.index;
        r.address = address;
        r.kind = a.capture;
        r.layout = a.layout;
        r.before.resize(n);
        if (n && !safe_copy(r.before.data(), reinterpret_cast<const void*>(address), n)) {
            continue;  // unreadable: not captured, so a replay that reads it is inconclusive
        }
        call->regions.push_back(std::move(r));
    }
    f->call = call;
    return site.real;
}

// Called by record_thunk.asm after the original returned: the memory again, then the test case.
extern "C" void pbeta_record_after(RecordFrame* f) {
    auto* call = static_cast<RecordCall*>(f->call);
    if (!call) {
        return;
    }
    finish_case(call, f);
    delete call;
}

namespace {

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
    g_image_base = reinterpret_cast<unsigned long long>(GetModuleHandleW(nullptr));
    CreateDirectoryA(g_rec_dir.c_str(), nullptr);
    CreateDirectoryA((g_rec_dir + "\\cases").c_str(), nullptr);
    CreateDirectoryA((g_rec_dir + "\\blobs").c_str(), nullptr);
    CopyFileA(path.c_str(), (g_rec_dir + "\\spec.toml").c_str(), FALSE);

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
