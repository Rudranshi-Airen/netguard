/*
 * bitset.h -- Fixed-width bit vectors.
 *
 * NFA state sets in the subset construction are variable-width word arrays
 * (bs_* functions over uint64_t*).  Rule sets (at most NG_MAX_RULES = 2048
 * rules) use the fixed-size RuleSet.
 */
#ifndef NG_BITSET_H
#define NG_BITSET_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <string.h>

#define BS_WORDS(nbits) (((size_t)(nbits) + 63) / 64)

static inline void bs_set(uint64_t *w, int i) { w[i >> 6] |= (uint64_t)1 << (i & 63); }
static inline int  bs_test(const uint64_t *w, int i) { return (int)((w[i >> 6] >> (i & 63)) & 1u); }
int      bs_empty(const uint64_t *w, size_t nwords);
int      bs_lowest(const uint64_t *w, size_t nwords);    /* -1 if empty */
int      bs_next(const uint64_t *w, size_t nwords, int after); /* next set bit > after, or -1 */
uint64_t bs_hash(const uint64_t *w, size_t nwords, uint64_t seed);

/* 2048 rules = 32 words of 64 bits each */
#define RS_WORDS 32
typedef struct { uint64_t w[RS_WORDS]; } RuleSet;       /* up to 2048 rules */
static inline void rs_clear(RuleSet *s) { memset(s->w, 0, sizeof s->w); }
static inline void rs_set(RuleSet *s, int i) { bs_set(s->w, i); }
static inline int  rs_test(const RuleSet *s, int i) { return bs_test(s->w, i); }
static inline int  rs_lowest(const RuleSet *s) { return bs_lowest(s->w, RS_WORDS); }
static inline int  rs_next(const RuleSet *s, int after) { return bs_next(s->w, RS_WORDS, after); }
int rs_count(const RuleSet *s);

#endif
