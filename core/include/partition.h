/*
 * partition.h -- Interval partitioning of every field domain into the
 * alphabet symbols of the automata.
 */
#ifndef NG_PARTITION_H
#define NG_PARTITION_H

#include <stdint.h>
#include "ir.h"

typedef struct { uint32_t lo, hi; } Interval;

typedef struct {
    int       nsyms;       /* number of intervals == number of symbols */
    Interval *iv;          /* sorted, disjoint, covering the domain */
    int       offset;      /* global id of local symbol 0 */
} FieldPart;

typedef struct {
    int       nfields;
    FieldPart f[NG_MAX_FIELDS];
    int       total_syms;  /* size of the union alphabet */
    int      *sym_field;   /* global symbol -> field */
    int      *sym_local;   /* global symbol -> local index */
    uint64_t  cells;       /* product of nsyms (saturates at UINT64_MAX) */
} Partition;

void partition_build(Partition *pt, const Policy *p);
void partition_free(Partition *pt);
/* Local symbol of value v on field k (binary search), -1 if outside the domain. */
int  partition_lookup(const Partition *pt, int k, uint32_t v);
/* Local symbols [*first, *last] whose union is exactly r.  Returns 0 if r
 * is an exact union of whole intervals, -1 otherwise. */
int  partition_span(const Partition *pt, int k, Range r, int *first, int *last);

#endif
