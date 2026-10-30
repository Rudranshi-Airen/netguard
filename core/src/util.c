/*
 * util.c -- Portable helpers used by every phase.
 *
 * Nothing algorithmic lives here: checked allocation, string helpers, IPv4
 * formatting, a growable string buffer, Levenshtein distance (used only to
 * suggest a keyword in lexical diagnostics, O(|a|*|b|)), and the splitmix64
 * PRNG used by random verification.
 */
#include "util.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fputs("netguard: out of memory\n", stderr); exit(3); }
    return p;
}

void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) { fputs("netguard: out of memory\n", stderr); exit(3); }
    return p;
}

void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fputs("netguard: out of memory\n", stderr); exit(3); }
    return q;
}

char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = xmalloc(n);
    memcpy(d, s, n);
    return d;
}

int str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++; b++;
    }
    return *a == *b;
}

void str_copy(char *dst, const char *src, size_t cap) {
    if (cap == 0) return;
    size_t n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

void ip_to_str(uint32_t ip, char *buf, size_t cap) {
    snprintf(buf, cap, "%u.%u.%u.%u", (unsigned)(ip >> 24), (unsigned)((ip >> 16) & 255),
             (unsigned)((ip >> 8) & 255), (unsigned)(ip & 255));
}

int ip_parse(const char *s, uint32_t *out) {
    uint32_t ip = 0;
    for (int k = 0; k < 4; k++) {
        if (!isdigit((unsigned char)*s)) return -1;
        uint32_t v = 0;
        int digits = 0;
        while (isdigit((unsigned char)*s)) {
            v = v * 10 + (uint32_t)(*s - '0');
            if (++digits > 3 || v > 255) return -1;
            s++;
        }
        ip = (ip << 8) | v;
        if (k < 3) {
            if (*s != '.') return -1;
            s++;
        }
    }
    if (*s) return -1;
    *out = ip;
    return 0;
}

int u32_parse(const char *s, uint32_t *out) {
    uint64_t v = 0;
    if (!*s) return -1;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s)) return -1;
        v = v * 10 + (uint64_t)(*s - '0');
        if (v > 0xFFFFFFFFull) return -1;
    }
    *out = (uint32_t)v;
    return 0;
}

int edit_distance(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    if (la > 31 || lb > 31) return 99;
    int d[32][32];
    for (size_t i = 0; i <= la; i++) d[i][0] = (int)i;
    for (size_t j = 0; j <= lb; j++) d[0][j] = (int)j;
    for (size_t i = 1; i <= la; i++)
        for (size_t j = 1; j <= lb; j++) {
            int cost = tolower((unsigned char)a[i - 1]) != tolower((unsigned char)b[j - 1]);
            int best = d[i - 1][j] + 1;
            if (d[i][j - 1] + 1 < best) best = d[i][j - 1] + 1;
            if (d[i - 1][j - 1] + cost < best) best = d[i - 1][j - 1] + cost;
            d[i][j] = best;
        }
    return d[la][lb];
}

void sb_init(StrBuf *sb) { sb->data = NULL; sb->len = sb->cap = 0; }
void sb_free(StrBuf *sb) { free(sb->data); sb_init(sb); }

static void sb_reserve(StrBuf *sb, size_t extra) {
    if (sb->len + extra + 1 <= sb->cap) return;
    size_t cap = sb->cap ? sb->cap : 256;
    while (cap < sb->len + extra + 1) cap *= 2;
    sb->data = xrealloc(sb->data, cap);
    sb->cap = cap;
}

void sb_putc(StrBuf *sb, char c) {
    sb_reserve(sb, 1);
    sb->data[sb->len++] = c;
    sb->data[sb->len] = '\0';
}

void sb_puts(StrBuf *sb, const char *s) {
    size_t n = strlen(s);
    sb_reserve(sb, n);
    memcpy(sb->data + sb->len, s, n + 1);
    sb->len += n;
}

void sb_printf(StrBuf *sb, const char *fmt, ...) {
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        sb_reserve(sb, (size_t)n);
        vsnprintf(sb->data + sb->len, (size_t)n + 1, fmt, ap2);
        sb->len += (size_t)n;
    }
    va_end(ap2);
}

char *sb_take(StrBuf *sb) {
    char *d = sb->data ? sb->data : xstrdup("");
    sb_init(sb);
    return d;
}

uint64_t rng_next(Rng *r) {
    uint64_t z = (r->s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

uint64_t rng_range(Rng *r, uint64_t lo, uint64_t hi) {
    uint64_t span = hi - lo + 1;
    if (span == 0) return rng_next(r);          /* full 64-bit range */
    return lo + rng_next(r) % span;
}

long clock_now(void) { return (long)clock(); }

double ms_since(long start_clock) {
    return (double)((long)clock() - start_clock) * 1000.0 / (double)CLOCKS_PER_SEC;
}

char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    StrBuf sb;
    sb_init(&sb);
    char chunk[4096];
    size_t n;
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        sb_reserve(&sb, n);
        memcpy(sb.data + sb.len, chunk, n);
        sb.len += n;
        sb.data[sb.len] = '\0';
    }
    fclose(f);
    return sb_take(&sb);
}
