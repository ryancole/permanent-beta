// Sample app for the M4 hook-repair loop (corpus/hooks/README.md), version 1.
//
// A tiny order-processing run with a fixed script, so every run prints the same thing and the hooked functions
// see the same arguments. The hook targets are extern "C" (stable names for the answer key) and
// noinline (so they stay functions under /O2).

#include <cstdio>
#include <cstring>

#define HOOKABLE extern "C" __declspec(noinline)

struct Order {
    int id;
    int count;
    int skus[8];
    int qtys[8];
    int total;
};

static int g_events = 0;

HOOKABLE void log_event(const char* msg, int code) {
    g_events++;
    std::printf("[event %d] %s (%d)\n", g_events, msg, code);
}

HOOKABLE int price_lookup(int sku) {
    return 100 + (sku * 37) % 900;
}

HOOKABLE int stock_level(int sku) {
    int s = sku ^ 0x5a;
    if (s < 0) {
        s = -s;
    }
    int level = s % 50;
    if (sku & 1) {
        level += 3;
    }
    return level;
}

HOOKABLE int apply_discount(int cents, int percent) {
    return cents - cents * percent / 100;
}

HOOKABLE int order_add(Order* o, int sku, int qty) {
    if (o->count >= 8) {
        log_event("order full", o->id);
        return -1;
    }
    int available = stock_level(sku);
    if (qty > available) {
        qty = available;
    }
    o->skus[o->count] = sku;
    o->qtys[o->count] = qty;
    o->count++;
    return qty;
}

HOOKABLE int format_receipt(char* buf, int cap, const Order* o, const char* customer) {
    return std::snprintf(buf, static_cast<size_t>(cap), "Receipt #%d for %s: %d lines, total %d.%02d", o->id,
        customer, o->count, o->total / 100, o->total % 100);
}

HOOKABLE unsigned checksum(const unsigned char* data, int len) {
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

HOOKABLE unsigned ship_order(Order* o, const char* customer, int discount) {
    int total = 0;
    for (int i = 0; i < o->count; i++) {
        total += price_lookup(o->skus[i]) * o->qtys[i];
    }
    o->total = apply_discount(total, discount);
    char receipt[128];
    int n = format_receipt(receipt, sizeof receipt, o, customer);
    std::printf("%s\n", receipt);
    unsigned sum = checksum(reinterpret_cast<const unsigned char*>(receipt), n);
    log_event("shipped", o->id);
    return sum;
}

int main() {
    static const char* const customers[] = {"Ada", "Grace", "Linus"};
    unsigned combined = 0;
    for (int id = 1; id <= 3; id++) {
        Order o{};
        o.id = id;
        for (int line = 0; line < 3 + id * 2; line++) {
            order_add(&o, id * 10 + line, line + id);
        }
        combined ^= ship_order(&o, customers[id - 1], id * 5);
    }
    std::printf("combined checksum %08x\n", combined);
    return 0;
}
