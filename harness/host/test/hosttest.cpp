// Test app for the hook host (harness/host/test.ps1). Its functions are the prototype shapes the generic thunk has
// to get right: stack arguments (5 to 12 parameters), float and double arguments and results in xmm registers,
// integer and float slots mixed, a void result, strings, recursion, and calls from several threads. It prints each
// result, so a register or stack the thunk corrupts shows up as a wrong number, not only as a strange log line.
//
// Built twice: `/DV2` adds a function and a call before the others, so every function moves.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <cwchar>

#define NOINLINE extern "C" __declspec(noinline)

#ifdef V2
NOINLINE int banner(int x) {
    return x * 3 + 1;
}
#endif

NOINLINE int add3(int a, int b, int c) {
    return a + b + c;
}

// Weighted, so arguments in the wrong order give another result: with 1..12, 1·1 + 2·2 + … + 12·12 = 650.
NOINLINE long long sum12(long long a1, long long a2, long long a3, long long a4, long long a5, long long a6,
                         long long a7, long long a8, long long a9, long long a10, long long a11, long long a12) {
    return a1 * 1 + a2 * 2 + a3 * 3 + a4 * 4 + a5 * 5 + a6 * 6 + a7 * 7 + a8 * 8 + a9 * 9 + a10 * 10 + a11 * 11 +
           a12 * 12;
}

// Integer and float slots mixed: a in rcx, b in xmm1, c in r8, d in xmm3; the result in xmm0.
NOINLINE double mix(int a, double b, int c, float d) {
    return a + b * c + d;
}

NOINLINE float scalef(float x, float y) {
    return x * y;
}

volatile int g_stores;

// Counts its calls too: `*out = v` alone is 3 bytes at /O2, too short for a 5-byte entry patch (pbeta sends a
// hook on it to review as not hookable).
NOINLINE void store(int* out, int v) {
    *out = v;
    g_stores = g_stores + 1;
}

NOINLINE size_t count_chars(const char* s, const wchar_t* w) {
    return std::strlen(s) + std::wcslen(w);
}

// Direct recursion: each call fib makes to itself goes through the hook (pbeta takes a call to a function's own
// entry as hookable; a jump back to it, a loop, is not).
NOINLINE unsigned long long fib(unsigned n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

namespace {

constexpr int kThreads = 4;
constexpr int kCalls = 1000;
long long g_totals[kThreads];

DWORD WINAPI worker(LPVOID p) {
    int index = static_cast<int>(reinterpret_cast<INT_PTR>(p));
    long long total = 0;
    for (int i = 0; i < kCalls; i++) {
        total += add3(i, 1, 1);
    }
    g_totals[index] = total;
    return 0;
}

}  // namespace

int main() {
#ifdef V2
    std::printf("banner %d\n", banner(2));
#endif
    std::printf("add3 %d\n", add3(2, 3, 4));
    std::printf("add3 %d\n", add3(-1, -2, 3));
    std::printf("sum12 %lld\n", sum12(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12));
    std::printf("mix %g\n", mix(2, 1.5, 3, 0.25f));
    std::printf("scalef %g\n", static_cast<double>(scalef(1.5f, 4.0f)));
    int x = 0;
    store(&x, 7);
    std::printf("store %d\n", x);
    std::printf("count_chars %zu\n", count_chars("hello", L"wörld"));
    std::printf("fib %llu\n", fib(10));

    HANDLE threads[kThreads];
    for (int t = 0; t < kThreads; t++) {
        threads[t] = CreateThread(nullptr, 0, worker, reinterpret_cast<LPVOID>(static_cast<INT_PTR>(t)), 0, nullptr);
    }
    WaitForMultipleObjects(kThreads, threads, TRUE, INFINITE);
    long long all = 0;
    for (int t = 0; t < kThreads; t++) {
        CloseHandle(threads[t]);
        all += g_totals[t];
    }
    std::printf("threads %lld\n", all);
    return 0;
}
