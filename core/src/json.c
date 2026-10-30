/*
 * json.c -- Hand-written streaming JSON writer.
 *
 * Algorithm.  A depth-indexed counter tells whether a comma is needed
 * before the next value (or key); a flag suppresses it right after a key.
 * Strings are escaped per RFC 8259: '"' and '\\' are backslash-escaped,
 * control characters use \n \r \t \b \f or \u00XX, and the UTF-8 input is
 * validated: well-formed multi-byte sequences are copied verbatim, every
 * malformed byte becomes U+FFFD so the output is always valid UTF-8 JSON
 * (user source can contain arbitrary bytes).
 *
 * Complexity: O(output size).
 *
 * Compiler-design concept: code emission / serialization -- the "back end"
 * that writes the compiler's results in a target format.
 */
#include "json.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

void json_init(Json *j) {
    sb_init(&j->sb);
    j->depth = 0;
    j->count[0] = 0;
    j->after_key = 0;
}

void json_free(Json *j) { sb_free(&j->sb); }
char *json_take(Json *j) { return sb_take(&j->sb); }

static void before_value(Json *j) {
    if (j->after_key) { j->after_key = 0; return; }
    if (j->count[j->depth]++ > 0) sb_putc(&j->sb, ',');
}

static void begin(Json *j, char c) {
    before_value(j);
    sb_putc(&j->sb, c);
    if (j->depth < JSON_MAX_DEPTH - 1) j->depth++;
    j->count[j->depth] = 0;
}

static void finish(Json *j, char c) {
    if (j->depth > 0) j->depth--;
    sb_putc(&j->sb, c);
}

void json_obj(Json *j) { begin(j, '{'); }
void json_end_obj(Json *j) { finish(j, '}'); }
void json_arr(Json *j) { begin(j, '['); }
void json_end_arr(Json *j) { finish(j, ']'); }

/* Length of a well-formed UTF-8 sequence at s, or 0 if malformed. */
static int utf8_len(const unsigned char *s) {
    if (s[0] < 0x80) return 1;
    int n;
    unsigned min;
    unsigned cp;
    if ((s[0] & 0xE0) == 0xC0) { n = 2; cp = s[0] & 0x1Fu; min = 0x80; }
    else if ((s[0] & 0xF0) == 0xE0) { n = 3; cp = s[0] & 0x0Fu; min = 0x800; }
    else if ((s[0] & 0xF8) == 0xF0) { n = 4; cp = s[0] & 0x07u; min = 0x10000; }
    else return 0;
    for (int i = 1; i < n; i++) {
        if ((s[i] & 0xC0) != 0x80) return 0;
        cp = (cp << 6) | (s[i] & 0x3Fu);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
    return n;
}

static void write_string(StrBuf *sb, const char *str) {
    const unsigned char *s = (const unsigned char *)str;
    sb_putc(sb, '"');
    while (*s) {
        unsigned char c = *s;
        switch (c) {
        case '"': sb_puts(sb, "\\\""); s++; continue;
        case '\\': sb_puts(sb, "\\\\"); s++; continue;
        case '\n': sb_puts(sb, "\\n"); s++; continue;
        case '\r': sb_puts(sb, "\\r"); s++; continue;
        case '\t': sb_puts(sb, "\\t"); s++; continue;
        case '\b': sb_puts(sb, "\\b"); s++; continue;
        case '\f': sb_puts(sb, "\\f"); s++; continue;
        default: break;
        }
        if (c < 0x20) {
            sb_printf(sb, "\\u%04x", (unsigned)c);
            s++;
            continue;
        }
        int n = utf8_len(s);
        if (n == 0) {
            sb_puts(sb, "\\ufffd");
            s++;
            continue;
        }
        for (int i = 0; i < n; i++) sb_putc(sb, (char)s[i]);
        s += n;
    }
    sb_putc(sb, '"');
}

void json_key(Json *j, const char *k) {
    before_value(j);
    write_string(&j->sb, k);
    sb_putc(&j->sb, ':');
    j->after_key = 1;
}

void json_str(Json *j, const char *s) {
    before_value(j);
    write_string(&j->sb, s ? s : "");
}

void json_int(Json *j, long long v) {
    before_value(j);
    sb_printf(&j->sb, "%lld", v);
}

void json_u64(Json *j, uint64_t v) {
    before_value(j);
    sb_printf(&j->sb, "%llu", (unsigned long long)v);
}

void json_num(Json *j, double v) {
    before_value(j);
    if (!isfinite(v)) sb_puts(&j->sb, "null");
    else sb_printf(&j->sb, "%.3f", v);
}

void json_bool(Json *j, int v) {
    before_value(j);
    sb_puts(&j->sb, v ? "true" : "false");
}

void json_null(Json *j) {
    before_value(j);
    sb_puts(&j->sb, "null");
}

void json_kstr(Json *j, const char *k, const char *s) { json_key(j, k); json_str(j, s); }
void json_kint(Json *j, const char *k, long long v) { json_key(j, k); json_int(j, v); }
void json_ku64(Json *j, const char *k, uint64_t v) { json_key(j, k); json_u64(j, v); }
void json_knum(Json *j, const char *k, double v) { json_key(j, k); json_num(j, v); }
void json_kbool(Json *j, const char *k, int v) { json_key(j, k); json_bool(j, v); }
void json_knull(Json *j, const char *k) { json_key(j, k); json_null(j); }
