/*
 * minimize.h -- Hopcroft minimization of a complete DFA.
 */
#ifndef NG_MINIMIZE_H
#define NG_MINIMIZE_H

#include "dfa.h"

typedef enum {
    MIN_BY_ACTION = 0,   /* initial blocks: bottom + one per action (minimal classifier) */
    MIN_BY_RULE   = 1    /* initial blocks: bottom + one per winner (keeps rule identity) */
} MinMode;

/* out := minimal DFA equivalent to in w.r.t. the chosen output.  Start is
 * state 0; states are numbered in BFS order. */
void dfa_minimize(DFA *out, const DFA *in, MinMode mode);

#endif
