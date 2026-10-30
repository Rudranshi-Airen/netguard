/*
 * partition.c -- Sweep-line interval partitioning (alphabet construction).
 *
 * Algorithm.  For each field k independently:
 *   1. collect the cut points  domain.lo, domain.hi+1  and, for every rule,
 *      cond[k].lo and cond[k].hi+1   (64-bit, since hi+1 may be 2^32);
 *   2. sort them and remove duplicates;
 *   3. sweep left to right: consecutive cut points c_j < c_{j+1} give the
 *      interval [c_j, c_{j+1}-1].
 * The result is the minimal partition of the domain into disjoint
 * intervals such that every rule's range is an exact union of whole
 * intervals: no interval straddles a rule boundary, and every interior cut
 * point is a boundary of some rule, which covers exactly one of the two
 * neighbouring intervals, so no two adjacent intervals can be merged.
 * Each interval becomes
 * one alphabet symbol (field k, local index j); global symbol ids number
 * all fields' symbols consecutively, giving the union alphabet.
 *
 * This is exactly flex's "character classes" (equivalence classes of
 * input characters that no pattern distinguishes), lifted from bytes to
 * 32-bit field values: the automata are built over a few hundred symbols
 * instead of 2^32 values.
 *
 * lookup(field, value) is a binary search over the sorted intervals.
 * The cell count is the product of the per-field symbol counts: the number
 * of distinct symbol strings, i.e. of packet equivalence classes.
 *
 * Complexity: O(R log R) per field to sort 2R+2 cut points; O(log R) per
 * lookup.
 *
 * Compiler-design concept: alphabet compression / character classes.
 */
#include "partition.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

void partition_build(Partition *pt, const Policy *p) {
    memset(pt, 0, sizeof *pt);
    pt->nfields = p->nfields;
    pt->cells = 1;
    int offset = 0;
    for (int k = 0; k < p->nfields; k++) {
        size_t n = 0, cap = 2 + 2 * (size_t)p->nrules;
        uint64_t *cuts = xmalloc(sizeof(uint64_t) * cap);
        Range dom = p->fields[k].domain;
        cuts[n++] = dom.lo;
        cuts[n++] = (uint64_t)dom.hi + 1;
        for (int i = 0; i < p->nrules; i++) {
            cuts[n++] = p->rules[i].cond[k].lo;
            cuts[n++] = (uint64_t)p->rules[i].cond[k].hi + 1;
        }
        qsort(cuts, n, sizeof(uint64_t), cmp_u64);
        size_t m = 0;
        for (size_t i = 0; i < n; i++)
            if (m == 0 || cuts[i] != cuts[m - 1]) cuts[m++] = cuts[i];
        FieldPart *fp = &pt->f[k];
        fp->nsyms = (int)m - 1;
        fp->iv = xmalloc(sizeof(Interval) * (size_t)fp->nsyms);
        for (int j = 0; j < fp->nsyms; j++) {
            fp->iv[j].lo = (uint32_t)cuts[j];
            fp->iv[j].hi = (uint32_t)(cuts[j + 1] - 1);
        }
        fp->offset = offset;
        offset += fp->nsyms;
        if (pt->cells != UINT64_MAX) {
            if (pt->cells > UINT64_MAX / (uint64_t)fp->nsyms) pt->cells = UINT64_MAX;
            else pt->cells *= (uint64_t)fp->nsyms;
        }
        free(cuts);
    }
    pt->total_syms = offset;
    pt->sym_field = xmalloc(sizeof(int) * (size_t)(offset ? offset : 1));
    pt->sym_local = xmalloc(sizeof(int) * (size_t)(offset ? offset : 1));
    for (int k = 0; k < p->nfields; k++)
        for (int j = 0; j < pt->f[k].nsyms; j++) {
            pt->sym_field[pt->f[k].offset + j] = k;
            pt->sym_local[pt->f[k].offset + j] = j;
        }
}

void partition_free(Partition *pt) {
    for (int k = 0; k < pt->nfields; k++) free(pt->f[k].iv);
    free(pt->sym_field);
    free(pt->sym_local);
    memset(pt, 0, sizeof *pt);
}

int partition_lookup(const Partition *pt, int k, uint32_t v) {
    const FieldPart *fp = &pt->f[k];
    int lo = 0, hi = fp->nsyms - 1;
    while (lo <= hi) {
        int mid = lo + (hi - lo) / 2;
        if (v < fp->iv[mid].lo) hi = mid - 1;
        else if (v > fp->iv[mid].hi) lo = mid + 1;
        else return mid;
    }
    return -1;
}

int partition_span(const Partition *pt, int k, Range r, int *first, int *last) {
    int a = partition_lookup(pt, k, r.lo), b = partition_lookup(pt, k, r.hi);
    if (a < 0 || b < 0) return -1;
    *first = a;
    *last = b;
    return (pt->f[k].iv[a].lo == r.lo && pt->f[k].iv[b].hi == r.hi) ? 0 : -1;
}
