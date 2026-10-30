/*
 * nfa.h -- Thompson NFA over the partition alphabet.
 */
#ifndef NG_NFA_H
#define NG_NFA_H

#include "ir.h"
#include "partition.h"

#define NFA_EPS (-1)

typedef struct { int to, sym; } NfaEdge;   /* sym: global symbol or NFA_EPS */

typedef struct {
    int      nstates, start;
    int     *accept;       /* rule index accepted in this state, or -1 */
    int     *layer;        /* symbols consumed on any path to the state */
    int     *rule_of;      /* rule whose fragment owns the state (-1: start) */
    int     *edge_start;   /* CSR: edges of s are edges[edge_start[s] .. edge_start[s+1]) */
    NfaEdge *edges;
    int      nedges, eps_edges, sym_edges;
} NFA;

/* Returns 0, or -1 if the NFA would exceed NG_MAX_NFA_STATES (*needed is
 * then the number of states it would have had). */
int  nfa_build(NFA *n, const Policy *p, const Partition *pt, int *needed);
void nfa_free(NFA *n);

#endif
