/*
 * dfa.h -- Layered complete DFA built by the subset construction.
 *
 * The same structure also holds minimized DFAs (minimize.c), where
 * `matched`, `parent` and `nfa_size` are NULL.
 */
#ifndef NG_DFA_H
#define NG_DFA_H

#include "bitset.h"
#include "ir.h"
#include "nfa.h"
#include "partition.h"

#define OUT_BOTTOM   (-1)   /* output of a non-final state */
#define WIN_NONFINAL (-2)   /* winner of a non-final state */

typedef struct {
    int      nstates, nsyms, nfields;
    int      start, sink;
    int     *trans;        /* trans[s * nsyms + g]: complete over the union alphabet */
    int     *layer;        /* symbols consumed (0..nfields); -1 for SINK */
    int     *output;       /* action index at the final layer, OUT_BOTTOM elsewhere */
    int     *winner;       /* lowest matched rule, -1 (DEFAULT) or WIN_NONFINAL */
    RuleSet *matched;      /* rules accepted in a final-layer state (unminimized only) */
    int     *parent;       /* BFS tree (unminimized only): predecessor state */
    int     *parent_sym;   /*   ... and the symbol read from it */
    int     *nfa_size;     /* |NFA state set| (unminimized only) */
    int      cap;
} DFA;

/* Subset construction.  Returns 0, -1 if NG_MAX_DFA_STATES would be
 * exceeded, -2 if the transition table would exceed dfa_max_trans_cells(). */
int  dfa_build(DFA *d, const NFA *n, const Policy *p, const Partition *pt);
void dfa_free(DFA *d);
/* Memory cap on states * symbols (env NETGUARD_MAX_TRANS_CELLS, default 60M). */
long dfa_max_trans_cells(void);
int  dfa_final_count(const DFA *d);
/* Run the DFA on the symbols of a packet; returns the state reached.
 * states_out (optional) receives the nfields+1 visited states. */
int  dfa_run(const DFA *d, const Partition *pt, const uint32_t *vals, int *states_out);
/* A concrete packet that reaches state s (unminimized DFA: uses parent
 * pointers; each symbol becomes its interval's lo value). */
void dfa_witness(const DFA *d, const Partition *pt, int s, uint32_t *vals);

#endif
