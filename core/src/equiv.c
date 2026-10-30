/*
 * equiv.c -- Policy equivalence by product-automaton search.
 *
 * Algorithm.  Two policies are equivalent iff they decide every packet the
 * same way.  Both are compiled over ONE common alphabet: the original
 * policy's partition.  That partition is valid for any subset of the
 * original rules, because it refines the partition each subset would build
 * on its own (every cut point of a subset is a cut point of the whole), so
 * every rule of either policy is an exact union of its intervals.  Each
 * policy is compiled to its action-minimized complete DFA, and we explore
 * the product automaton breadth-first:
 *
 *     start (qA0, qB0); from (p, q) on symbol a go to (dA(p,a), dB(q,a))
 *     if some reachable pair has outputA(p) != outputB(q): NOT equivalent
 *
 * Both DFAs are complete over the same alphabet, so the product is complete
 * and explores exactly the pairs of states reachable by a common word.
 * BFS parent pointers rebuild the shortest distinguishing symbol string,
 * which is turned into a concrete counterexample packet by taking each
 * symbol's interval lo value.  (When the policies are arbitrary rather than
 * a policy and its subset, equiv_policies uses the partition of A u B,
 * which refines both.)
 *
 * Complexity: O(|A| * |B| * |Sigma|) time in the worst case, usually far
 * less because only reachable pairs are visited; the pair set is a hash.
 *
 * Compiler-design concept: language equivalence of DFAs via the product
 * construction (bisimulation check), used here as translation validation:
 * proving the optimized program equivalent to the original.
 */
#include "equiv.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int compile_policy(Compiled *c, const Policy *p, const Partition *pt, int want_min, char *msg, int msgcap) {
    memset(c, 0, sizeof *c);
    int needed = 0;
    if (nfa_build(&c->nfa, p, pt, &needed) != 0) {
        snprintf(msg, (size_t)msgcap, "the Thompson NFA would need %d states (limit %d)", needed, NG_MAX_NFA_STATES);
        return -1;
    }
    int drc = dfa_build(&c->dfa, &c->nfa, p, pt);
    if (drc != 0) {
        if (drc == -2)
            snprintf(msg, (size_t)msgcap, "the DFA transition table would exceed %ld cells (memory cap)", dfa_max_trans_cells());
        else
            snprintf(msg, (size_t)msgcap, "the subset construction exceeded %d DFA states", NG_MAX_DFA_STATES);
        return -1;
    }
    if (want_min) {
        dfa_minimize(&c->min, &c->dfa, MIN_BY_ACTION);
        c->has_min = 1;
    }
    return 0;
}

void compiled_free(Compiled *c) {
    nfa_free(&c->nfa);
    dfa_free(&c->dfa);
    if (c->has_min) dfa_free(&c->min);
    memset(c, 0, sizeof *c);
}

typedef struct { int a, b, parent, sym; } Pair;

/* Visited set of state pairs: BFS queue + open-addressing hash index. */
typedef struct {
    Pair *q;
    int n, cap;
    int *table;
    size_t tcap;
} PairSet;

static size_t pair_hash(int a, int b) { return ((size_t)a * 2654435761u) ^ ((size_t)b * 40503u); }

static void pairset_reindex(PairSet *ps, size_t tcap) {
    free(ps->table);
    ps->tcap = tcap;
    ps->table = xmalloc(sizeof(int) * tcap);
    for (size_t i = 0; i < tcap; i++) ps->table[i] = -1;
    for (int k = 0; k < ps->n; k++) {
        size_t h = pair_hash(ps->q[k].a, ps->q[k].b) & (tcap - 1);
        while (ps->table[h] >= 0) h = (h + 1) & (tcap - 1);
        ps->table[h] = k;
    }
}

/* Enqueue (a, b) unless already visited. */
static void pairset_push(PairSet *ps, int a, int b, int parent, int sym) {
    size_t h = pair_hash(a, b) & (ps->tcap - 1);
    while (ps->table[h] >= 0) {
        const Pair *p = &ps->q[ps->table[h]];
        if (p->a == a && p->b == b) return;
        h = (h + 1) & (ps->tcap - 1);
    }
    if (ps->n == ps->cap) {
        ps->cap = ps->cap ? ps->cap * 2 : 256;
        ps->q = xrealloc(ps->q, sizeof(Pair) * (size_t)ps->cap);
    }
    ps->q[ps->n] = (Pair){a, b, parent, sym};
    ps->table[h] = ps->n++;
    if ((size_t)ps->n * 2 > ps->tcap) pairset_reindex(ps, ps->tcap * 2);
}

void equiv_dfas(EquivResult *res, const DFA *A, const DFA *B, const Partition *pt) {
    memset(res, 0, sizeof *res);
    res->equivalent = 1;
    int S = A->nsyms;
    PairSet ps = {NULL, 0, 0, NULL, 0};
    pairset_reindex(&ps, 1024);
    pairset_push(&ps, A->start, B->start, -1, -1);
    for (int head = 0; head < ps.n; head++) {
        Pair cur = ps.q[head];
        if (A->output[cur.a] != B->output[cur.b]) {
            res->equivalent = 0;
            res->has_counterexample = 1;
            res->action_a = A->output[cur.a];
            res->action_b = B->output[cur.b];
            for (int k = 0; k < pt->nfields; k++) res->packet[k] = pt->f[k].iv[0].lo;
            for (int i = head; ps.q[i].parent >= 0; i = ps.q[i].parent) {
                int g = ps.q[i].sym, k = pt->sym_field[g];
                res->packet[k] = pt->f[k].iv[pt->sym_local[g]].lo;
            }
            break;
        }
        for (int g = 0; g < S; g++)
            pairset_push(&ps, A->trans[(size_t)cur.a * S + g], B->trans[(size_t)cur.b * S + g], head, g);
    }
    res->pairs_explored = ps.n;
    free(ps.q);
    free(ps.table);
}

int equiv_with(EquivResult *res, const DFA *amin, const Policy *b, const Partition *pt) {
    Compiled cb;
    char msg[160];
    if (compile_policy(&cb, b, pt, 1, msg, sizeof msg) != 0) {
        compiled_free(&cb);
        memset(res, 0, sizeof *res);
        return -1;
    }
    equiv_dfas(res, amin, &cb.min, pt);
    compiled_free(&cb);
    return 0;
}

int equiv_policies(EquivResult *res, const Policy *a, const Policy *b) {
    /* Partition of A u B: refines both policies' own partitions. */
    Policy u;
    policy_copy(&u, a);
    for (int i = 0; i < b->nrules; i++) policy_add_rule(&u, &b->rules[i]);
    Partition pt;
    partition_build(&pt, &u);
    policy_free(&u);
    Compiled ca;
    char msg[160];
    int rc = compile_policy(&ca, a, &pt, 1, msg, sizeof msg);
    if (rc == 0) rc = equiv_with(res, &ca.min, b, &pt);
    compiled_free(&ca);
    partition_free(&pt);
    return rc;
}
