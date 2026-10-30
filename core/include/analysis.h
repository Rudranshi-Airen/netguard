/*
 * analysis.h -- Shadow / redundancy analysis on the unminimized DFA.
 */
#ifndef NG_ANALYSIS_H
#define NG_ANALYSIS_H

#include "bitset.h"
#include "equiv.h"
#include "ir.h"
#include "partition.h"

typedef enum { ST_OK = 0, ST_SHADOWED, ST_PARTIAL, ST_REDUNDANT } RuleStatus;

typedef struct {
    RuleStatus status;
    int  conflicting;         /* a covering / beating rule has a different action */
    int  union_shadow;        /* shadowed: 1 = only a union of rules covers it */
    int  container;           /* shadowed single-rule: the earlier rule that contains it */
    const char *severity;     /* "high" | "medium" | "low" | "none" */
    char subtype[48];
    int  win_states, lose_states;   /* final-layer DFA states where it wins / loses */
    RuleSet covered_by;       /* shadowed: winners of the states where it matches */
    RuleSet beaten_by;        /* all rules that win where it matches but loses */
    RuleSet deciders;         /* redundant: later rules deciding its packets without it */
    int  default_decides;     /* redundant: ... or the DEFAULT */
    int  has_example;         /* a concrete packet illustrating the status */
    uint32_t example[NG_MAX_FIELDS];
    int  example_winner;      /* who decides the example in the original policy */
    int  removal_checked;     /* the "remove it alone" equivalence check ran */
    int  has_cx;              /* ... and was NOT equivalent: counterexample */
    uint32_t cx[NG_MAX_FIELDS];
    int  cx_winner_without;   /* rule (original index) deciding cx once it is removed, -1 = DEFAULT */
    char explanation[900];
} RuleReport;

typedef struct {
    int nrules;
    RuleReport *r;
    int count[4];             /* indexed by RuleStatus */
    int conflicting, high;
} Analysis;

/* c must hold the unminimized DFA and the action-minimized DFA of p over pt. */
int  analysis_run(Analysis *a, const Policy *p, const Partition *pt, const Compiled *c);
void analysis_free(Analysis *a);
const char *status_name(RuleStatus s);
/* Rules (other than `removed`) that decide the packets currently won by
 * rule `removed` once it is deleted, scanned on the unminimized DFA d. */
void deciders_after_removal(const DFA *d, int removed, RuleSet *out, int *uses_default);
/* "R5, R6" / "R5 (ALLOW), R6 (ALLOW)" */
void ruleset_names(const Policy *p, const RuleSet *s, int with_action, char *buf, int n);
/* Old recompile-per-rule redundancy check; kept for differential test only.
 * Returns 1=redundant, 0=not redundant, -1=limits exceeded. */
int analysis_redundancy_equiv_check(const Policy *p, const Partition *pt, const Compiled *c, int i);

#endif
