/*
 * bitset.c -- Bit-vector operations.
 *
 * Sets of NFA states are the "states" of the subset construction, so the
 * DFA builder spends most of its time here: hashing (FNV-1a over 64-bit
 * words, O(words)), emptiness and lowest-bit queries (O(words)).
 */
#include "bitset.h"

int bs_empty(const uint64_t *w, size_t nwords) {
    for (size_t i = 0; i < nwords; i++)
        if (w[i]) return 0;
    return 1;
}

static int lowest_bit(uint64_t x) {
    int b = 0;
    while (!(x & 1u)) { x >>= 1; b++; }
    return b;
}

int bs_lowest(const uint64_t *w, size_t nwords) {
    for (size_t i = 0; i < nwords; i++)
        if (w[i]) return (int)(i * 64) + lowest_bit(w[i]);
    return -1;
}

int bs_next(const uint64_t *w, size_t nwords, int after) {
    int start = after + 1;
    size_t wi = (size_t)start >> 6;
    if (wi >= nwords) return -1;
    uint64_t cur = w[wi] & (~(uint64_t)0 << (start & 63));
    for (;;) {
        if (cur) return (int)(wi * 64) + lowest_bit(cur);
        if (++wi >= nwords) return -1;
        cur = w[wi];
    }
}

uint64_t bs_hash(const uint64_t *w, size_t nwords, uint64_t seed) {
    uint64_t h = 1469598103934665603ull ^ seed;
    for (size_t i = 0; i < nwords; i++) {
        h ^= w[i];
        h *= 1099511628211ull;
        h ^= h >> 29;
    }
    return h;
}

int rs_count(const RuleSet *s) {
    int n = 0;
    for (int i = 0; i < RS_WORDS; i++) {
        uint64_t x = s->w[i];
        while (x) { x &= x - 1; n++; }
    }
    return n;
}
