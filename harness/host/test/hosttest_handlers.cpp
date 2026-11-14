// Handlers for the hook host test (harness/host/test.ps1): one that replaces the original, and two that call
// through to it (one with stack arguments, one with float arguments and a double result).

#include <pbeta_handler.h>

// Replaces add3: the product instead of the sum.
PBETA_HOOK(int, add3, (int a, int b, int c)) {
    return a * b * c;
}

// Calls through with all twelve arguments (eight on the stack), then adds 1.
PBETA_HOOK(long long, sum12,
           (long long a1, long long a2, long long a3, long long a4, long long a5, long long a6, long long a7,
            long long a8, long long a9, long long a10, long long a11, long long a12)) {
    long long r = PBETA_ORIGINAL(sum12)(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
    pbeta_log("handler: sum12 -> %lld", r);
    return r + 1;
}

// Calls through with mixed slots, then doubles the result.
PBETA_HOOK(double, mix, (int a, double b, int c, float d)) {
    return PBETA_ORIGINAL(mix)(a, b, c, d) * 2;
}
