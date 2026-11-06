// Permanent Beta test fixture "basic", version 2.
// Each pb_* function is one matching scenario; see ../README.md. Keep v1 and v2 in sync with that table.
// extern "C" keeps symbol names identical across signature changes, so the map-file answer key can join by name.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#define NOINLINE __declspec(noinline)

struct Config {
    int a;
    int inserted;  // S5: new field shifts `b` from offset 4 to offset 8.
    int b;
};

extern "C" {

// S9 added: exists only in v2. Placed first so everything after it moves.
NOINLINE int pb_added(int x) {
    int acc = 1;
    for (int i = 1; i <= x; ++i) {
        acc = (acc * 31 + i) & 0xffff;
    }
    return acc;
}

// S1 unchanged: identical source in v1 and v2.
NOINLINE int pb_unchanged(int x) {
    int acc = 0;
    for (int i = 0; i < x; ++i) {
        acc += i * 3 + 1;
    }
    return acc;
}

// S2 moved: identical source, but code was added before it so its address changes.
NOINLINE int pb_moved(int x) {
    return (x * 7) ^ (x >> 2);
}

// S3 body edited: same name and signature, different arithmetic.
NOINLINE int pb_body_edited(int x) {
    return (x * 9 - 4) ^ 0x55;
}

// S4 parameter added: gained a third parameter.
NOINLINE int pb_param_added(int a, int b, int c) {
    return a * b - (a + b) + c;
}

// S5 struct layout changed: same source, but `b` is now at a different offset.
NOINLINE int pb_struct_reader(const Config* c) {
    return c->b * 2 + c->a;
}

// S6 identical copies: two functions with identical bodies. /OPT:ICF may fold them into one.
NOINLINE int pb_dup_a(int x) {
    return (x * 13 + 5) % 97;
}

NOINLINE int pb_dup_b(int x) {
    return (x * 13 + 5) % 97;
}

}  // extern "C"

// S8 static with unique strings: internal linkage, identified only by the strings it references.
extern "C" {
static NOINLINE int pb_static_strings(const char* name) {
    if (std::strcmp(name, "pb-config.ini") == 0) {
        return 1;
    }
    if (std::strcmp(name, "[pb-settings]") == 0) {
        return 2;
    }
    return 0;
}
}  // extern "C"

int main(int argc, char** argv) {
    // Inputs come from argc/argv so the optimizer can't constant-fold the calls away.
    const int x = argc + 2;
    Config cfg{x, 0, x + 1};
    int total = 0;
    total += pb_added(x);
    total += pb_unchanged(x);
    total += pb_moved(x);
    total += pb_body_edited(x);
    total += pb_param_added(x, x + 1, x + 2);
    total += pb_struct_reader(&cfg);
    total += pb_dup_a(x);
    total += pb_dup_b(x + 1);
    total += pb_static_strings(argc > 1 ? argv[1] : "pb-config.ini");
    std::printf("%d\n", total);
    return EXIT_SUCCESS;
}
