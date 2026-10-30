/*
 * optimize.h -- Rule-removal optimizer with a removal log.
 */
#ifndef NG_OPTIMIZE_H
#define NG_OPTIMIZE_H

#include "analysis.h"
#include "equiv.h"
#include "ir.h"

typedef struct {
    int  index;               /* original rule index */
    char phase[16];           /* "shadowed" | "redundant" */
    char reason[900];
} Removal;

typedef struct {
    int original_rules, optimized_rules;
    unsigned char keep[NG_MAX_RULES];
    Removal *removed;
    int nremoved;
    Policy optimized;
    char *source;             /* optimized policy as .fw / .ng text */
} Optimization;

int  optimize_run(Optimization *o, const Policy *p, Syntax syn, const Partition *pt,
                  const Compiled *orig, const Analysis *an);
void optimize_free(Optimization *o);
/* Old equivalence-per-rule phase 2, kept for the differential test only. */
int  optimize_keep_equiv(const Policy *p, const Partition *pt, const Compiled *orig, unsigned char *keep);

#endif
