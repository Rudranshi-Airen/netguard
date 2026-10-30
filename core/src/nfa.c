/*
 * nfa.c -- Thompson's construction of an epsilon-NFA for the whole policy.
 *
 * Algorithm.  A packet is the symbol string s0 s1 ... s(n-1): one alphabet
 * symbol per field, in field order.  The language of rule r is therefore
 *
 *     L(r) = A0 . A1 . ... . A(n-1)     where Ak = (a | b | ...) is the set
 *                                       of field-k symbols covering cond[k]
 *
 * and is built with the strict Thompson rules:
 *   - symbol a:          s --a--> f                       (2 states)
 *   - alternation of m:  new s, new f, s --eps--> each fragment start,
 *                        each fragment end --eps--> f     (an m-way union is
 *                        the usual binary rule applied at once); when a
 *                        field has a single covering symbol the fragment is
 *                        just that symbol
 *   - concatenation:     end of A(k) --eps--> start of A(k+1)
 * The end state of rule r's fragment is tagged accept = r.index.  All rule
 * fragments are joined by a fresh start state with eps-edges (the union of
 * all rule languages).  Epsilon edges are kept explicit; they are removed
 * later by the epsilon-closure inside the subset construction.
 *
 * Because every rule range is an exact union of partition intervals, the
 * NFA accepts the symbol string of a packet with tag r iff rule r matches
 * that packet.  Priority is not encoded here: the NFA may accept a string
 * with several tags, and the subset construction keeps them all.
 *
 * Complexity: O(sum over rules and fields of the covering symbol count)
 * states and edges, i.e. O(R * |Sigma|) in the worst case.
 *
 * Compiler-design concept: Thompson's construction (regular expression to
 * epsilon-NFA), exactly as a scanner generator builds one NFA per token
 * pattern and joins them under a common start state.
 */
#include "nfa.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

typedef struct { int from, to, sym; } RawEdge;

typedef struct {
    NFA *n;
    int cap;
    RawEdge *raw;
    int nraw, capraw;
} Builder;

static int new_state(Builder *b, int layer, int rule) {
    NFA *n = b->n;
    if (n->nstates == b->cap) {
        b->cap = b->cap ? b->cap * 2 : 64;
        n->accept = xrealloc(n->accept, sizeof(int) * (size_t)b->cap);
        n->layer = xrealloc(n->layer, sizeof(int) * (size_t)b->cap);
        n->rule_of = xrealloc(n->rule_of, sizeof(int) * (size_t)b->cap);
    }
    n->accept[n->nstates] = -1;
    n->layer[n->nstates] = layer;
    n->rule_of[n->nstates] = rule;
    return n->nstates++;
}

static void add_edge(Builder *b, int from, int to, int sym) {
    if (b->nraw == b->capraw) {
        b->capraw = b->capraw ? b->capraw * 2 : 128;
        b->raw = xrealloc(b->raw, sizeof(RawEdge) * (size_t)b->capraw);
    }
    b->raw[b->nraw++] = (RawEdge){from, to, sym};
    if (sym == NFA_EPS) b->n->eps_edges++;
    else b->n->sym_edges++;
}

/* Thompson fragment for field k of rule r: returns start, *end receives end. */
static int field_fragment(Builder *b, const Partition *pt, int k, int first, int last, int rule, int *end) {
    int off = pt->f[k].offset;
    if (first == last) {                           /* single symbol: s --a--> f */
        int s = new_state(b, k, rule), f = new_state(b, k + 1, rule);
        add_edge(b, s, f, off + first);
        *end = f;
        return s;
    }
    int s = new_state(b, k, rule), f = new_state(b, k + 1, rule);   /* alternation */
    for (int j = first; j <= last; j++) {
        int fs = new_state(b, k, rule), fe = new_state(b, k + 1, rule);
        add_edge(b, s, fs, NFA_EPS);
        add_edge(b, fs, fe, off + j);
        add_edge(b, fe, f, NFA_EPS);
    }
    *end = f;
    return s;
}

int nfa_build(NFA *n, const Policy *p, const Partition *pt, int *needed) {
    memset(n, 0, sizeof *n);
    /* Size check first, so an oversized policy is rejected cheaply. */
    long total = 1;
    for (int r = 0; r < p->nrules; r++)
        for (int k = 0; k < p->nfields; k++) {
            int a, z;
            partition_span(pt, k, p->rules[r].cond[k], &a, &z);
            total += (a == z) ? 2 : 2 + 2L * (z - a + 1);
        }
    if (needed) *needed = (int)(total > 2000000000L ? 2000000000L : total);
    if (total > NG_MAX_NFA_STATES) return -1;

    Builder b = {n, 0, NULL, 0, 0};
    n->start = new_state(&b, 0, -1);
    for (int r = 0; r < p->nrules; r++) {
        int rule_start = -1, prev_end = -1;
        for (int k = 0; k < p->nfields; k++) {
            int a, z, end;
            partition_span(pt, k, p->rules[r].cond[k], &a, &z);
            int s = field_fragment(&b, pt, k, a, z, r, &end);
            if (prev_end < 0) rule_start = s;
            else add_edge(&b, prev_end, s, NFA_EPS);      /* concatenation */
            prev_end = end;
        }
        add_edge(&b, n->start, rule_start, NFA_EPS);     /* union under the start state */
        n->accept[prev_end] = r;
    }

    /* Counting sort the edges into CSR form (stable: keeps creation order). */
    n->nedges = b.nraw;
    n->edge_start = xcalloc((size_t)n->nstates + 1, sizeof(int));
    n->edges = xmalloc(sizeof(NfaEdge) * (size_t)(b.nraw ? b.nraw : 1));
    for (int i = 0; i < b.nraw; i++) n->edge_start[b.raw[i].from + 1]++;
    for (int s = 0; s < n->nstates; s++) n->edge_start[s + 1] += n->edge_start[s];
    int *fill = xmalloc(sizeof(int) * (size_t)n->nstates);
    for (int s = 0; s < n->nstates; s++) fill[s] = n->edge_start[s];
    for (int i = 0; i < b.nraw; i++) n->edges[fill[b.raw[i].from]++] = (NfaEdge){b.raw[i].to, b.raw[i].sym};
    free(fill);
    free(b.raw);
    return 0;
}

void nfa_free(NFA *n) {
    free(n->accept);
    free(n->layer);
    free(n->rule_of);
    free(n->edge_start);
    free(n->edges);
    memset(n, 0, sizeof *n);
}
