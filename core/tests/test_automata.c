/*
 * test_automata.c -- Thompson NFA, subset construction, Hopcroft minimization.
 *
 *  - hand-checked state / edge counts on tiny policies;
 *  - Hopcroft's result has the same size as an independent (naive Moore)
 *    minimization;
 *  - on random policies of up to 6 rules, the minimized DFA, the
 *    unminimized DFA and the linear oracle agree on every cell
 *    representative (both ends of every interval).
 */
#include "oracle.h"
#include "test.h"
#include "util.h"

#include <stdlib.h>

static void build(Pipeline *pl, const char *src) {
    pipeline_run(pl, src, SYNTAX_NG, MIN_BY_ACTION, RUN_AUTOMATA);
    CHECK(pl->built);
}

/* Naive Moore refinement: number of classes of the coarsest stable partition. */
static int moore_classes(const DFA *d, MinMode mode) {
    int n = d->nstates, S = d->nsyms;
    int *cls = xmalloc(sizeof(int) * (size_t)n), *nc = xmalloc(sizeof(int) * (size_t)n);
    for (int s = 0; s < n; s++) {
        int key = d->output[s] == OUT_BOTTOM ? -3 : (mode == MIN_BY_ACTION ? d->output[s] : d->winner[s]);
        cls[s] = key + 3;
    }
    int count = -1;
    for (;;) {
        int m = 0;
        for (int s = 0; s < n; s++) {
            nc[s] = -1;
            for (int t = 0; t < s && nc[s] < 0; t++) {
                int same = cls[s] == cls[t];
                for (int g = 0; g < S && same; g++)
                    same = cls[d->trans[(size_t)s * S + g]] == cls[d->trans[(size_t)t * S + g]];
                if (same) nc[s] = nc[t];
            }
            if (nc[s] < 0) nc[s] = m++;
        }
        memcpy(cls, nc, sizeof(int) * (size_t)n);
        if (m == count) break;
        count = m;
    }
    free(cls);
    free(nc);
    return count;
}

static void check_counts(const char *src, int nfa, int eps, int sym, int dfa, int finals, int min_act, int min_rule) {
    Pipeline pl;
    build(&pl, src);
    if (pl.built) {
        CHECK_EQ(pl.c.nfa.nstates, nfa);
        CHECK_EQ(pl.c.nfa.eps_edges, eps);
        CHECK_EQ(pl.c.nfa.sym_edges, sym);
        CHECK_EQ(pl.c.dfa.nstates, dfa);
        CHECK_EQ(dfa_final_count(&pl.c.dfa), finals);
        CHECK_EQ(pl.c.min.nstates, min_act);
        CHECK_EQ(pl.min_rule.nstates, min_rule);
        CHECK_EQ(moore_classes(&pl.c.dfa, MIN_BY_ACTION), min_act);
        CHECK_EQ(moore_classes(&pl.c.dfa, MIN_BY_RULE), min_rule);
    }
    pipeline_free(&pl);
}

/* Evaluate every cell (both ends of every interval) three ways. */
static void check_agreement(const Pipeline *pl) {
    const Policy *p = &pl->pol;
    const Partition *pt = &pl->pt;
    int idx[NG_MAX_FIELDS] = {0};
    uint32_t vals[NG_MAX_FIELDS];
    for (;;) {
        for (int end = 0; end < 2; end++) {
            for (int k = 0; k < p->nfields; k++) vals[k] = end ? pt->f[k].iv[idx[k]].hi : pt->f[k].iv[idx[k]].lo;
            int ow;
            int o = oracle_eval(p, vals, &ow);
            int ms = dfa_run(&pl->c.min, pt, vals, NULL);
            int ds = dfa_run(&pl->c.dfa, pt, vals, NULL);
            int rs = dfa_run(&pl->min_rule, pt, vals, NULL);
            CHECK_EQ(pl->c.min.output[ms], o);
            CHECK_EQ(pl->c.dfa.output[ds], o);
            CHECK_EQ(pl->c.dfa.winner[ds], ow);
            CHECK_EQ(pl->min_rule.winner[rs], ow);
            for (int i = 0; i < p->nrules; i++) {
                int m = 1;
                for (int k = 0; k < p->nfields; k++) m &= rule_field_contains(&p->rules[i], k, vals[k]);
                CHECK_EQ(rs_test(&pl->c.dfa.matched[ds], i), m);
            }
        }
        int k = 0;
        while (k < p->nfields && ++idx[k] == pt->f[k].nsyms) idx[k++] = 0;
        if (k == p->nfields) break;
    }
}

void test_automata(void) {
    /* one field, one rule:  start --eps--> s --[0-4]--> f(R a)
       DFA: {start,s}, {f} (X), {} (default Y), SINK. */
    check_counts("ruleset t; field f : 0 .. 9; default Y; rule a : X when f in 0 .. 4;", 3, 1, 1, 4, 2, 4, 4);
    /* same, but default X: both final states output X and merge by action */
    check_counts("ruleset t; field f : 0 .. 9; default X; rule a : X when f in 0 .. 4;", 3, 1, 1, 4, 2, 3, 4);
    /* two fields */
    check_counts("ruleset t; field a : 0 .. 1; field b : 0 .. 1; default B; rule r : A when a == 0;", 5, 2, 2, 6, 2, 6, 6);
    check_counts("ruleset t; field a : 0 .. 1; field b : 0 .. 1; default A; rule r : A when a == 0;", 5, 2, 2, 6, 2, 4, 6);
    /* overlapping rules: Thompson alternation for 2-symbol ranges */
    check_counts("ruleset t; field f : 0 .. 9; default Z; rule r1 : X when f in 0 .. 4; rule r2 : Y when f in 3 .. 9;",
                 13, 10, 4, 5, 3, 4, 4);
    /* no rules: start, layer-1 empty set (DEFAULT), SINK */
    check_counts("ruleset t; field f : 0 .. 9; default Z;", 1, 0, 0, 3, 1, 3, 3);

    /* The firewall example: Hopcroft vs Moore, and full agreement on all cells. */
    char *src = load_example("firewall_anomalies.fw");
    Pipeline pl;
    pipeline_run(&pl, src, SYNTAX_FW, MIN_BY_ACTION, RUN_AUTOMATA);
    CHECK(pl.built);
    CHECK_EQ(moore_classes(&pl.c.dfa, MIN_BY_ACTION), pl.c.min.nstates);
    CHECK_EQ(moore_classes(&pl.c.dfa, MIN_BY_RULE), pl.min_rule.nstates);
    CHECK_EQ(pl.c.dfa.layer[pl.c.dfa.sink], -1);
    for (int g = 0; g < pl.c.dfa.nsyms; g++)            /* completeness: SINK loops on everything */
        CHECK_EQ(pl.c.dfa.trans[(size_t)pl.c.dfa.sink * pl.c.dfa.nsyms + g], pl.c.dfa.sink);
    check_agreement(&pl);
    pipeline_free(&pl);
    free(src);

    /* Random policies of 1..6 rules over 1..3 small fields. */
    Rng rng = {12345};
    int before = g_failures;
    for (int iter = 0; iter < 300 && g_failures == before; iter++) {
        StrBuf sb;
        sb_init(&sb);
        int nf = 1 + (int)(rng_next(&rng) % 3), nr = 1 + (int)(rng_next(&rng) % 6);
        sb_puts(&sb, "ruleset r;\n");
        int dmax[3];
        for (int k = 0; k < nf; k++) {
            dmax[k] = 5 + (int)(rng_next(&rng) % 20);
            sb_printf(&sb, "field f%d : 0 .. %d;\n", k, dmax[k]);
        }
        sb_printf(&sb, "default A%d;\n", (int)(rng_next(&rng) % 3));
        for (int i = 0; i < nr; i++) {
            sb_printf(&sb, "rule q%d : A%d when", i, (int)(rng_next(&rng) % 3));
            int any = 0;
            for (int k = 0; k < nf; k++) {
                if (any && rng_next(&rng) % 3 == 0) continue;
                int lo = (int)(rng_next(&rng) % 6), hi = lo + (int)(rng_next(&rng) % 6);
                if (hi > dmax[k]) hi = dmax[k];
                sb_printf(&sb, "%s f%d in %d .. %d", any ? " and" : "", k, lo, hi);
                any = 1;
            }
            sb_puts(&sb, ";\n");
        }
        Pipeline rp;
        pipeline_run(&rp, sb.data, SYNTAX_NG, MIN_BY_ACTION, RUN_AUTOMATA);
        CHECK(rp.built);
        if (rp.built) {
            check_agreement(&rp);
            CHECK_EQ(moore_classes(&rp.c.dfa, MIN_BY_ACTION), rp.c.min.nstates);
            CHECK_EQ(moore_classes(&rp.c.dfa, MIN_BY_RULE), rp.min_rule.nstates);
        }
        if (g_failures != before) fprintf(stderr, "  failing random policy:\n%s\n", sb.data);
        pipeline_free(&rp);
        sb_free(&sb);
    }
}
