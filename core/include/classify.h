/*
 * classify.h -- Explainable packet classification.
 */
#ifndef NG_CLASSIFY_H
#define NG_CLASSIFY_H

#include "dfa.h"
#include "ir.h"
#include "partition.h"

typedef struct {
    int      field;
    uint32_t value;
    int      sym, gsym;          /* local / global symbol */
    Interval iv;
    int      from, to;           /* minimized-DFA states */
    int      dfa_from, dfa_to;   /* unminimized-DFA states */
} TraceStep;

typedef struct { int rule, field; } Failure;   /* first failing field of an earlier rule */

typedef struct {
    int       decision;          /* action index, from the minimized DFA */
    int       winner;            /* from the unminimized DFA; -1 = DEFAULT */
    RuleSet   matched;
    int       min_final, dfa_final;
    TraceStep trace[NG_MAX_FIELDS];
    Failure   fails[NG_MAX_RULES];
    int       nfails;
    int       oracle_decision, oracle_winner;
} Classification;

void classify_packet(Classification *c, const Policy *p, const Partition *pt, const DFA *min,
                     const DFA *dfa, const uint32_t *vals);
/* Parse "proto=TCP src_ip=10.1.2.3 dst_ip=8.8.8.8 dst_port=22" (values may be
 * numbers, dotted IPv4 or protocol names; every field is required).
 * Returns 0, or -1 with a message in err. */
int  parse_packet(const Policy *p, const char *text, uint32_t *vals, char *err, int errcap);

#endif
