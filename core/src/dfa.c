/*
 * dfa.c -- Subset construction (epsilon-NFA to DFA).
 *
 * Algorithm.  A DFA state is a pair (layer, T): T is a set of NFA states
 * (a bitset) and layer is the number of symbols consumed so far.
 *   start   = (0, eps-closure({nfa.start}))
 *   for a state (L, T) with L < nfields and each symbol a of field L:
 *       U = eps-closure( move(T, a) )   ->   transition to (L+1, U)
 * States are interned in a hash table keyed on (layer, T), so each distinct
 * pair is created once; the worklist is processed in creation (BFS) order,
 * which also records a BFS tree (parent, symbol) used to rebuild witness
 * packets.  The empty set is an ordinary state, one per layer ("no rule
 * alive"): it walks to the empty final-layer state, where the DEFAULT
 * decides.
 *
 * Every final-layer state (layer == nfields) stores
 *     matched = { accept tags of the NFA states in T }   (rules matching)
 *     winner  = lowest index in matched, or -1            (first match wins)
 *     output  = actions[winner], or default_action if winner == -1
 * Other layers output "bottom" (no decision yet).
 *
 * Completeness: the union alphabet contains the symbols of all fields.  A
 * symbol of the wrong field (any symbol at the final layer, or a field-j
 * symbol at layer L != j) goes to one global SINK state, which loops on
 * every symbol and outputs bottom.  So delta is total on every state and
 * the DFA is a complete DFA over the union alphabet.
 *
 * Complexity: worst case exponential in the number of NFA states (the
 * classic subset blow-up), bounded here by NG_MAX_DFA_STATES.  In practice
 * the layering and the partition keep it small.  Per created state the
 * cost is O(|T| + edges) for move/closure plus O(words) per hash probe.
 *
 * Compiler-design concept: subset (powerset) construction with
 * epsilon-closure, as performed by scanner generators (lex/flex) to turn
 * the combined token NFA into a DFA; `winner` mirrors flex's rule that the
 * earliest-listed pattern wins when several accept.
 */
#include "dfa.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

/* Cap on nstates * nsyms.  Each cell costs about 16 bytes at peak (the table
 * plus Hopcroft's inverse lists), so the default 60M cells is ~1 GB.  Small
 * servers lower it with the environment variable NETGUARD_MAX_TRANS_CELLS. */
#define DEFAULT_MAX_TRANS_CELLS 60000000L

long dfa_max_trans_cells(void) {
    const char *e = getenv("NETGUARD_MAX_TRANS_CELLS");
    long v = e ? strtol(e, NULL, 10) : 0;
    return v > 0 ? v : DEFAULT_MAX_TRANS_CELLS;
}

typedef struct {
    DFA *d;
    const NFA *n;
    size_t words;          /* words per NFA-state bitset */
    uint64_t *sets;        /* sets[s * words ...] */
    int *table;            /* open-addressing hash: DFA state ids, -1 = empty */
    size_t tcap;
    long max_cells;
    int hit_cell_cap;
} Builder;

static void grow(Builder *b) {
    DFA *d = b->d;
    int cap = d->cap ? d->cap * 2 : 64;
    d->trans = xrealloc(d->trans, sizeof(int) * (size_t)cap * (size_t)d->nsyms);
    d->layer = xrealloc(d->layer, sizeof(int) * (size_t)cap);
    d->output = xrealloc(d->output, sizeof(int) * (size_t)cap);
    d->winner = xrealloc(d->winner, sizeof(int) * (size_t)cap);
    d->matched = xrealloc(d->matched, sizeof(RuleSet) * (size_t)cap);
    d->parent = xrealloc(d->parent, sizeof(int) * (size_t)cap);
    d->parent_sym = xrealloc(d->parent_sym, sizeof(int) * (size_t)cap);
    d->nfa_size = xrealloc(d->nfa_size, sizeof(int) * (size_t)cap);
    b->sets = xrealloc(b->sets, sizeof(uint64_t) * (size_t)cap * b->words);
    d->cap = cap;
}

static uint64_t key_hash(const Builder *b, int layer, const uint64_t *set) {
    return bs_hash(set, b->words, (uint64_t)(layer + 1) * 0x9E3779B97F4A7C15ull);
}

static void rehash(Builder *b) {
    size_t ncap = b->tcap ? b->tcap * 2 : 256;
    int *nt = xmalloc(sizeof(int) * ncap);
    for (size_t i = 0; i < ncap; i++) nt[i] = -1;
    for (int s = 0; s < b->d->nstates; s++) {
        if (s == b->d->sink) continue;
        size_t h = (size_t)key_hash(b, b->d->layer[s], b->sets + (size_t)s * b->words) & (ncap - 1);
        while (nt[h] >= 0) h = (h + 1) & (ncap - 1);
        nt[h] = s;
    }
    free(b->table);
    b->table = nt;
    b->tcap = ncap;
}

/* Find or create the DFA state (layer, set).  Returns -1 on overflow. */
static int intern(Builder *b, int layer, const uint64_t *set, int parent, int psym) {
    DFA *d = b->d;
    size_t h = (size_t)key_hash(b, layer, set) & (b->tcap - 1);
    while (b->table[h] >= 0) {
        int s = b->table[h];
        if (d->layer[s] == layer && memcmp(b->sets + (size_t)s * b->words, set, b->words * sizeof(uint64_t)) == 0)
            return s;
        h = (h + 1) & (b->tcap - 1);
    }
    if (d->nstates >= NG_MAX_DFA_STATES) return -1;
    if ((long)(d->nstates + 1) * (long)d->nsyms > b->max_cells) {
        b->hit_cell_cap = 1;
        return -1;
    }
    if (d->nstates == d->cap) grow(b);
    int s = d->nstates++;
    memcpy(b->sets + (size_t)s * b->words, set, b->words * sizeof(uint64_t));
    d->layer[s] = layer;
    d->output[s] = OUT_BOTTOM;
    d->winner[s] = WIN_NONFINAL;
    rs_clear(&d->matched[s]);
    d->parent[s] = parent;
    d->parent_sym[s] = psym;
    int cnt = 0;
    for (size_t w = 0; w < b->words; w++) {
        uint64_t x = set[w];
        while (x) { x &= x - 1; cnt++; }
    }
    d->nfa_size[s] = cnt;
    b->table[h] = s;
    if ((size_t)d->nstates * 2 > b->tcap) rehash(b);
    return s;
}

/* In-place epsilon-closure of set, using stack as scratch (size nstates). */
static void eps_closure(const NFA *n, uint64_t *set, size_t words, int *stack) {
    int top = 0;
    for (int s = bs_lowest(set, words); s >= 0; s = bs_next(set, words, s)) stack[top++] = s;
    while (top > 0) {
        int s = stack[--top];
        for (int e = n->edge_start[s]; e < n->edge_start[s + 1]; e++) {
            if (n->edges[e].sym != NFA_EPS) continue;
            int t = n->edges[e].to;
            if (!bs_test(set, t)) { bs_set(set, t); stack[top++] = t; }
        }
    }
}

int dfa_build(DFA *d, const NFA *n, const Policy *p, const Partition *pt) {
    memset(d, 0, sizeof *d);
    d->nsyms = pt->total_syms;
    d->nfields = p->nfields;
    d->sink = -1;
    Builder b = {d, n, BS_WORDS(n->nstates), NULL, NULL, 0, dfa_max_trans_cells(), 0};
    if (b.words == 0) b.words = 1;
    rehash(&b);

    int maxsyms = 1;
    for (int k = 0; k < pt->nfields; k++)
        if (pt->f[k].nsyms > maxsyms) maxsyms = pt->f[k].nsyms;
    uint64_t *buckets = xcalloc((size_t)maxsyms * b.words, sizeof(uint64_t));
    int *stack = xmalloc(sizeof(int) * (size_t)(n->nstates ? n->nstates : 1));
    uint64_t *tmp = xcalloc(b.words, sizeof(uint64_t));
    int rc = 0;

    bs_set(tmp, n->start);
    eps_closure(n, tmp, b.words, stack);
    d->start = intern(&b, 0, tmp, -1, -1);

    /* The SINK is not in the hash table (its key would collide with nothing). */
    if (d->nstates == d->cap) grow(&b);
    d->sink = d->nstates++;
    memset(b.sets + (size_t)d->sink * b.words, 0, b.words * sizeof(uint64_t));
    d->layer[d->sink] = -1;
    d->output[d->sink] = OUT_BOTTOM;
    d->winner[d->sink] = WIN_NONFINAL;
    rs_clear(&d->matched[d->sink]);
    d->parent[d->sink] = -1;
    d->parent_sym[d->sink] = -1;
    d->nfa_size[d->sink] = 0;

    for (int cur = 0; cur < d->nstates; cur++) {
        int L = d->layer[cur];
        int *row;
        /* NB: d->trans may move when states are added, so re-derive row. */
        for (int g = 0; g < d->nsyms; g++) d->trans[(size_t)cur * d->nsyms + g] = d->sink;
        if (cur == d->sink) continue;
        if (L == d->nfields) {                          /* final layer: decide */
            const uint64_t *set = b.sets + (size_t)cur * b.words;
            for (int s = bs_lowest(set, b.words); s >= 0; s = bs_next(set, b.words, s))
                if (n->accept[s] >= 0) rs_set(&d->matched[cur], n->accept[s]);
            int w = rs_lowest(&d->matched[cur]);
            d->winner[cur] = w;
            d->output[cur] = w >= 0 ? p->rules[w].action : p->default_action;
            continue;
        }
        /* move(T, a) for every symbol a of field L at once */
        int nsy = pt->f[L].nsyms, off = pt->f[L].offset;
        memset(buckets, 0, sizeof(uint64_t) * (size_t)nsy * b.words);
        const uint64_t *set = b.sets + (size_t)cur * b.words;
        for (int s = bs_lowest(set, b.words); s >= 0; s = bs_next(set, b.words, s))
            for (int e = n->edge_start[s]; e < n->edge_start[s + 1]; e++) {
                int sym = n->edges[e].sym;
                if (sym == NFA_EPS || pt->sym_field[sym] != L) continue;
                bs_set(buckets + (size_t)(sym - off) * b.words, n->edges[e].to);
            }
        for (int j = 0; j < nsy; j++) {
            uint64_t *u = buckets + (size_t)j * b.words;
            eps_closure(n, u, b.words, stack);
            int t = intern(&b, L + 1, u, cur, off + j);
            if (t < 0) { rc = b.hit_cell_cap ? -2 : -1; goto done; }
            row = d->trans + (size_t)cur * d->nsyms;
            row[off + j] = t;
        }
    }
done:
    free(buckets);
    free(stack);
    free(tmp);
    free(b.sets);
    free(b.table);
    return rc;
}

void dfa_free(DFA *d) {
    free(d->trans);
    free(d->layer);
    free(d->output);
    free(d->winner);
    free(d->matched);
    free(d->parent);
    free(d->parent_sym);
    free(d->nfa_size);
    memset(d, 0, sizeof *d);
}

int dfa_final_count(const DFA *d) {
    int c = 0;
    for (int s = 0; s < d->nstates; s++)
        if (d->layer[s] == d->nfields) c++;
    return c;
}

int dfa_run(const DFA *d, const Partition *pt, const uint32_t *vals, int *states_out) {
    int s = d->start;
    if (states_out) states_out[0] = s;
    for (int k = 0; k < d->nfields; k++) {
        int j = partition_lookup(pt, k, vals[k]);
        s = d->trans[(size_t)s * d->nsyms + pt->f[k].offset + j];
        if (states_out) states_out[k + 1] = s;
    }
    return s;
}

void dfa_witness(const DFA *d, const Partition *pt, int s, uint32_t *vals) {
    while (d->parent[s] >= 0) {
        int g = d->parent_sym[s];
        int k = pt->sym_field[g];
        vals[k] = pt->f[k].iv[pt->sym_local[g]].lo;
        s = d->parent[s];
    }
}
