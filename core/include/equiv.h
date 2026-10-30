/*
 * equiv.h -- Compiling a policy to automata, and policy equivalence.
 */
#ifndef NG_EQUIV_H
#define NG_EQUIV_H

#include "dfa.h"
#include "ir.h"
#include "minimize.h"
#include "nfa.h"
#include "partition.h"

/* A policy compiled over a given partition. */
typedef struct {
    NFA nfa;
    DFA dfa;        /* unminimized, from the subset construction */
    DFA min;        /* Hopcroft-minimized by action */
    int has_min;
} Compiled;

/* Thompson + subset construction (+ minimization when want_min).
 * Returns 0, or -1 when a size limit is exceeded (msg explains). */
int  compile_policy(Compiled *c, const Policy *p, const Partition *pt, int want_min, char *msg, int msgcap);
void compiled_free(Compiled *c);

typedef struct {
    int      equivalent;
    int      has_counterexample;
    uint32_t packet[NG_MAX_FIELDS];
    int      action_a, action_b;     /* decisions of A and B on the packet */
    int      pairs_explored;
} EquivResult;

/* Product-automaton BFS over two complete min-DFAs on the same alphabet. */
void equiv_dfas(EquivResult *res, const DFA *a, const DFA *b, const Partition *pt);
/* Is policy B equivalent to the policy whose min-DFA is amin?  B is compiled
 * over pt (which must refine B's own partition).  Returns 0, -1 on limits. */
int  equiv_with(EquivResult *res, const DFA *amin, const Policy *b, const Partition *pt);
/* Convenience: compile both A and B over A's partition. */
int  equiv_policies(EquivResult *res, const Policy *a, const Policy *b);

#endif
