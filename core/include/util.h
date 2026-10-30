/*
 * util.h -- Portable helpers (C11 standard library only).
 *
 * Checked allocation, string helpers that are not in ISO C (strdup,
 * strcasecmp), IPv4 formatting, a growable string buffer and a small
 * deterministic PRNG (splitmix64) so random verification is reproducible on
 * every platform (rand() differs between libc implementations).
 */
#ifndef NG_UTIL_H
#define NG_UTIL_H

#include <stddef.h>
#include <stdint.h>

void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);

int  str_ieq(const char *a, const char *b);           /* case-insensitive == */
void str_copy(char *dst, const char *src, size_t cap);  /* always NUL-terminates */
void ip_to_str(uint32_t ip, char *buf, size_t cap);
/* Parse "a.b.c.d" (each 0..255).  Returns 0 on success. */
int  ip_parse(const char *s, uint32_t *out);
/* Parse a non-negative decimal integer that fits in uint32.  0 on success. */
int  u32_parse(const char *s, uint32_t *out);
int  edit_distance(const char *a, const char *b);      /* case-insensitive */

/* Growable string buffer. */
typedef struct { char *data; size_t len, cap; } StrBuf;
void sb_init(StrBuf *sb);
void sb_free(StrBuf *sb);
void sb_putc(StrBuf *sb, char c);
void sb_puts(StrBuf *sb, const char *s);
void sb_printf(StrBuf *sb, const char *fmt, ...);
char *sb_take(StrBuf *sb);                              /* caller frees */

/* splitmix64 PRNG */
typedef struct { uint64_t s; } Rng;
uint64_t rng_next(Rng *r);
uint64_t rng_range(Rng *r, uint64_t lo, uint64_t hi);  /* inclusive */

/* Milliseconds between two clock() readings. */
double ms_since(long start_clock);
long   clock_now(void);

/* Read a whole file; NULL on failure.  Caller frees. */
char *read_file(const char *path);

#endif
