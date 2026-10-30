/*
 * minimize.c -- Hopcroft's DFA minimization (worklist / partition refinement).
 *
 * Algorithm.  Start from the coarsest partition compatible with the output
 * function and refine it until it is stable:
 *
 *   P := states grouped by output                        (initial partition)
 *        MIN_BY_ACTION: one block for "bottom" (non-final states and SINK)
 *                       plus one block per action at the final layer;
 *        MIN_BY_RULE:   bottom plus one block per winner (rule or DEFAULT).
 *   W := all blocks of P except a largest one             (worklist)
 *   while W is not empty:
 *       remove a splitter block B from W
 *       for every symbol a:
 *           X := { s : delta(s, a) in B }                 (inverse image)
 *           for every block Y with  Y & X != {}  and  Y \ X != {}:
 *               split Y into Y & X and Y \ X  (the smaller half gets a new id)
 *               if Y is in W: add the new half to W
 *               else:         add the smaller half to W
 *
 * Adding only the smaller half ("process the smaller half") is what gives
 * Hopcroft's O(|Sigma| n log n) bound: a state can be in a newly queued
 * splitter at most log2(n) times.  The refinable-partition representation
 * (elements array + per-block [first, mid, end) ranges, marking by
 * swapping into the block prefix) makes each split cost O(|smaller half|).
 * Inverse transitions are precomputed in CSR form, grouped by target.
 *
 * The result is the unique minimal complete DFA computing the same output
 * function: blocks become states, the transition of a block is the
 * transition of any member (all members agree once stable).
 * MIN_BY_ACTION minimizes the classification function itself (states that
 * lead to the same ALLOW/DENY decisions merge even if different rules win);
 * MIN_BY_RULE keeps "which rule decided" observable, for explainability.
 *
 * Complexity: O(|Sigma| * n log n) time, O(|Sigma| * n) memory.
 *
 * Compiler-design concept: DFA minimization by partition refinement
 * (Myhill-Nerode equivalence), as used by scanner generators after the
 * subset construction.
 */
#include "minimize.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

typedef struct {
    int *elems, *pos, *blk;          /* refinable partition */
    int *first, *mid, *end;          /* per block: marked = [first, mid) */
    int nblocks;
    int *in_w, *wl, nwl;             /* worklist (stack of blocks) */
    int *touched, ntouched;
} Refiner;

static void mark(Refiner *r, int s) {
    int b = r->blk[s], i = r->pos[s];
    if (i < r->mid[b]) return;                   /* already marked */
    if (r->mid[b] == r->first[b]) r->touched[r->ntouched++] = b;
    int j = r->mid[b]++;
    int other = r->elems[j];
    r->elems[j] = s;  r->pos[s] = j;
    r->elems[i] = other; r->pos[other] = i;
}

static void push_w(Refiner *r, int b) {
    if (r->in_w[b]) return;
    r->in_w[b] = 1;
    r->wl[r->nwl++] = b;
}

/* Split every touched block into marked / unmarked parts. */
static void split_touched(Refiner *r) {
    for (int t = 0; t < r->ntouched; t++) {
        int b = r->touched[t];
        if (r->mid[b] == r->end[b]) { r->mid[b] = r->first[b]; continue; }   /* all marked */
        int nb = r->nblocks++;
        int marked = r->mid[b] - r->first[b], unmarked = r->end[b] - r->mid[b];
        if (marked <= unmarked) {                 /* new block = marked part */
            r->first[nb] = r->first[b];
            r->end[nb] = r->mid[b];
            r->first[b] = r->mid[b];
        } else {                                  /* new block = unmarked part */
            r->first[nb] = r->mid[b];
            r->end[nb] = r->end[b];
            r->end[b] = r->mid[b];
        }
        r->mid[b] = r->first[b];
        r->mid[nb] = r->first[nb];
        for (int i = r->first[nb]; i < r->end[nb]; i++) r->blk[r->elems[i]] = nb;
        r->in_w[nb] = 0;
        /* nb is the smaller half: queue it in both cases of Hopcroft's rule. */
        push_w(r, nb);
    }
    r->ntouched = 0;
}

/* Order (key, state) pairs by key, then by state id. */
static int cmp_key_ptr(const void *a, const void *b) {
    const long *x = a, *y = b;
    if (x[0] != y[0]) return x[0] < y[0] ? -1 : 1;
    return (x[1] > y[1]) - (x[1] < y[1]);
}

void dfa_minimize(DFA *out, const DFA *in, MinMode mode) {
    int n = in->nstates, S = in->nsyms;
    Refiner r;
    memset(&r, 0, sizeof r);
    r.elems = xmalloc(sizeof(int) * (size_t)n);
    r.pos = xmalloc(sizeof(int) * (size_t)n);
    r.blk = xmalloc(sizeof(int) * (size_t)n);
    r.first = xmalloc(sizeof(int) * (size_t)n);
    r.mid = xmalloc(sizeof(int) * (size_t)n);
    r.end = xmalloc(sizeof(int) * (size_t)n);
    r.in_w = xcalloc((size_t)n, sizeof(int));
    r.wl = xmalloc(sizeof(int) * (size_t)n);
    r.touched = xmalloc(sizeof(int) * (size_t)n);

    /* Initial partition: sort states by output key. */
    long *keys = xmalloc(sizeof(long) * 2 * (size_t)n);
    for (int s = 0; s < n; s++) {
        long key;
        if (in->output[s] == OUT_BOTTOM) key = -3;
        else key = (mode == MIN_BY_ACTION) ? in->output[s] : in->winner[s];   /* winner -1 = DEFAULT */
        keys[2 * s] = key;
        keys[2 * s + 1] = s;
    }
    qsort(keys, (size_t)n, 2 * sizeof(long), cmp_key_ptr);
    int largest = -1, largest_size = -1;
    for (int i = 0; i < n; i++) {
        int s = (int)keys[2 * i + 1];
        if (i == 0 || keys[2 * i] != keys[2 * (i - 1)]) {
            if (r.nblocks > 0) r.end[r.nblocks - 1] = i;
            r.first[r.nblocks] = r.mid[r.nblocks] = i;
            r.nblocks++;
        }
        r.elems[i] = s;
        r.pos[s] = i;
        r.blk[s] = r.nblocks - 1;
    }
    if (r.nblocks > 0) r.end[r.nblocks - 1] = n;
    free(keys);
    for (int b = 0; b < r.nblocks; b++)
        if (r.end[b] - r.first[b] > largest_size) { largest_size = r.end[b] - r.first[b]; largest = b; }
    for (int b = 0; b < r.nblocks; b++)
        if (b != largest) push_w(&r, b);

    /* Inverse transitions, CSR by target state: entries (source, symbol). */
    int *inv_start = xcalloc((size_t)n + 1, sizeof(int));
    for (long i = 0; i < (long)n * S; i++) inv_start[in->trans[i] + 1]++;
    for (int t = 0; t < n; t++) inv_start[t + 1] += inv_start[t];
    int *inv_src = xmalloc(sizeof(int) * (size_t)n * (size_t)(S ? S : 1));
    int *inv_sym = xmalloc(sizeof(int) * (size_t)n * (size_t)(S ? S : 1));
    int *fill = xmalloc(sizeof(int) * (size_t)n);
    for (int t = 0; t < n; t++) fill[t] = inv_start[t];
    for (int s = 0; s < n; s++)
        for (int g = 0; g < S; g++) {
            int t = in->trans[(size_t)s * S + g];
            inv_src[fill[t]] = s;
            inv_sym[fill[t]++] = g;
        }
    free(fill);

    /* Scratch: incoming edges of the splitter, bucketed by symbol. */
    int *cnt = xmalloc(sizeof(int) * (size_t)(S + 1));
    int *bucket = xmalloc(sizeof(int) * (size_t)n * (size_t)(S ? S : 1));
    int *splitter = xmalloc(sizeof(int) * (size_t)n);

    while (r.nwl > 0) {
        int B = r.wl[--r.nwl];
        r.in_w[B] = 0;
        int bsize = r.end[B] - r.first[B];
        memcpy(splitter, r.elems + r.first[B], sizeof(int) * (size_t)bsize);  /* B as it is now */
        memset(cnt, 0, sizeof(int) * (size_t)(S + 1));
        for (int i = 0; i < bsize; i++) {
            int t = splitter[i];
            for (int e = inv_start[t]; e < inv_start[t + 1]; e++) cnt[inv_sym[e] + 1]++;
        }
        for (int g = 0; g < S; g++) cnt[g + 1] += cnt[g];
        int total = cnt[S];
        for (int i = 0; i < bsize; i++) {
            int t = splitter[i];
            for (int e = inv_start[t]; e < inv_start[t + 1]; e++) bucket[cnt[inv_sym[e]]++] = inv_src[e];
        }
        /* cnt[g] now holds the end of symbol g's bucket; its start is cnt[g-1]. */
        int startg = 0;
        for (int g = 0; g < S && startg < total; g++) {
            int endg = cnt[g];
            for (int i = startg; i < endg; i++) mark(&r, bucket[i]);
            split_touched(&r);
            startg = endg;
        }
    }

    /* Build the quotient automaton; number blocks in BFS order from start. */
    int *newid = xmalloc(sizeof(int) * (size_t)r.nblocks);
    int *rep = xmalloc(sizeof(int) * (size_t)r.nblocks);
    for (int b = 0; b < r.nblocks; b++) newid[b] = -1;
    int m = 0;
    newid[r.blk[in->start]] = m;
    rep[m++] = in->start;
    for (int q = 0; q < m; q++) {
        int s = rep[q];
        for (int g = 0; g < S; g++) {
            int b = r.blk[in->trans[(size_t)s * S + g]];
            if (newid[b] < 0) { newid[b] = m; rep[m++] = in->trans[(size_t)s * S + g]; }
        }
    }
    memset(out, 0, sizeof *out);
    out->nstates = out->cap = m;
    out->nsyms = S;
    out->nfields = in->nfields;
    out->start = 0;
    out->sink = in->sink >= 0 ? newid[r.blk[in->sink]] : -1;
    out->trans = xmalloc(sizeof(int) * (size_t)m * (size_t)(S ? S : 1));
    out->layer = xmalloc(sizeof(int) * (size_t)m);
    out->output = xmalloc(sizeof(int) * (size_t)m);
    out->winner = xmalloc(sizeof(int) * (size_t)m);
    for (int q = 0; q < m; q++) {
        int s = rep[q];
        out->layer[q] = in->layer[s];
        out->output[q] = in->output[s];
        out->winner[q] = (mode == MIN_BY_RULE || in->output[s] == OUT_BOTTOM) ? in->winner[s] : WIN_NONFINAL;
        for (int g = 0; g < S; g++) out->trans[(size_t)q * S + g] = newid[r.blk[in->trans[(size_t)s * S + g]]];
    }

    free(newid); free(rep);
    free(cnt); free(bucket); free(splitter);
    free(inv_start); free(inv_src); free(inv_sym);
    free(r.elems); free(r.pos); free(r.blk); free(r.first); free(r.mid); free(r.end);
    free(r.in_w); free(r.wl); free(r.touched);
}
