/*
 * test_analysis.c -- Expected analysis / optimization results of the examples,
 * plus the P1-a differential test: scan-based vs equiv-based redundancy.
 */
#include "analysis.h"
#include "equiv.h"
#include "ir.h"
#include "parser_fw.h"
#include "parser_ng.h"
#include "partition.h"
#include "test.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

static const RuleReport *report(const Pipeline *pl, const char *id) {
    int i = rule_index(&pl->pol, id);
    CHECK(i >= 0);
    return i >= 0 ? &pl->an.r[i] : &pl->an.r[0];
}

static int set_is(const Pipeline *pl, const RuleSet *s, const char *ids) {
    RuleSet want;
    rs_clear(&want);
    char buf[128];
    str_copy(buf, ids, sizeof buf);
    for (char *t = strtok(buf, ","); t; t = strtok(NULL, ",")) {
        int i = rule_index(&pl->pol, t);
        if (i < 0) return 0;
        rs_set(&want, i);
    }
    return memcmp(&want, s, sizeof want) == 0;
}

static int removed_at(const Pipeline *pl, int step, const char *id) {
    return step < pl->opt.nremoved && strcmp(pl->pol.rules[pl->opt.removed[step].index].id, id) == 0;
}

void test_analysis(void) {
    Pipeline pl;
    char *src = load_example("firewall_anomalies.fw");
    pipeline_run(&pl, src, SYNTAX_FW, MIN_BY_ACTION, RUN_FULL);
    CHECK(pl.analysed);
    if (pl.analysed) {
        const RuleReport *r2 = report(&pl, "R2");
        CHECK_EQ(r2->status, ST_SHADOWED);
        CHECK_EQ(r2->union_shadow, 0);
        CHECK_EQ(r2->container, rule_index(&pl.pol, "R1"));
        CHECK_EQ(r2->conflicting, 1);
        CHECK_STR(r2->severity, "high");
        CHECK(set_is(&pl, &r2->covered_by, "R1"));

        const RuleReport *r7 = report(&pl, "R7");
        CHECK_EQ(r7->status, ST_SHADOWED);
        CHECK_EQ(r7->union_shadow, 1);
        CHECK_EQ(r7->conflicting, 0);
        CHECK(set_is(&pl, &r7->covered_by, "R5,R6"));

        const RuleReport *r8 = report(&pl, "R8");
        CHECK_EQ(r8->status, ST_REDUNDANT);
        CHECK_EQ(r8->default_decides, 1);
        CHECK_EQ(rs_lowest(&r8->deciders), -1);

        const RuleReport *r9 = report(&pl, "R9");
        CHECK_EQ(r9->status, ST_REDUNDANT);
        CHECK(set_is(&pl, &r9->deciders, "R10"));
        CHECK_EQ(r9->default_decides, 0);

        const char *ok_ids[] = {"R1", "R3", "R4", "R5", "R6", "R10"};
        for (int i = 0; i < 6; i++) CHECK_EQ(report(&pl, ok_ids[i])->status, ST_OK);
        CHECK_EQ(pl.an.count[ST_OK], 6);
        CHECK_EQ(pl.an.count[ST_SHADOWED], 2);
        CHECK_EQ(pl.an.count[ST_REDUNDANT], 2);
        CHECK_EQ(pl.an.count[ST_PARTIAL], 0);

        /* Optimization: R2, R7 (shadowed), then R9, R8 (redundant), then R1. */
        CHECK_EQ(pl.opt.nremoved, 5);
        CHECK(removed_at(&pl, 0, "R2"));
        CHECK(removed_at(&pl, 1, "R7"));
        CHECK(removed_at(&pl, 2, "R9"));
        CHECK(removed_at(&pl, 3, "R8"));
        CHECK(removed_at(&pl, 4, "R1"));
        if (pl.opt.nremoved == 5) {
            CHECK(strstr(pl.opt.removed[4].reason, "R2") != NULL);        /* explains the dependency on R2 */
            CHECK(strstr(pl.opt.removed[4].reason, "DEFAULT DENY") != NULL);
            CHECK_STR(pl.opt.removed[4].phase, "redundant-after");
        }
        CHECK_EQ(pl.opt.optimized.nrules, 5);
        const char *kept[] = {"R3", "R4", "R5", "R6", "R10"};
        for (int i = 0; i < 5 && i < pl.opt.optimized.nrules; i++) CHECK_STR(pl.opt.optimized.rules[i].id, kept[i]);
        CHECK_EQ(pl.eq.equivalent, 1);

        /* The emitted .fw text re-parses and is equivalent to the original. */
        Policy back;
        DiagList d;
        diag_init(&d);
        CHECK_EQ(parse_fw(pl.opt.source, &back, &d, NULL, NULL), 0);
        CHECK_EQ(back.nrules, 5);
        EquivResult er;
        CHECK_EQ(equiv_policies(&er, &pl.pol, &back), 0);
        CHECK_EQ(er.equivalent, 1);
        policy_free(&back);
        diag_free(&d);
    }
    pipeline_free(&pl);
    free(src);

    /* tax.ng */
    src = load_example("tax.ng");
    pipeline_run(&pl, src, SYNTAX_NG, MIN_BY_ACTION, RUN_FULL);
    CHECK(pl.analysed);
    if (pl.analysed) {
        const RuleReport *t5 = report(&pl, "t5");
        CHECK_EQ(t5->status, ST_SHADOWED);
        CHECK_EQ(t5->union_shadow, 0);
        CHECK_EQ(t5->container, rule_index(&pl.pol, "t3"));
        CHECK(set_is(&pl, &t5->covered_by, "t2,t3"));
        CHECK_EQ(t5->conflicting, 1);
        CHECK_STR(t5->severity, "high");

        const RuleReport *t2 = report(&pl, "t2");
        CHECK_EQ(t2->status, ST_PARTIAL);
        CHECK(set_is(&pl, &t2->beaten_by, "t1"));

        CHECK_EQ(pl.opt.optimized.nrules, 4);
        CHECK_EQ(pl.eq.equivalent, 1);
        Policy back;
        DiagList d;
        diag_init(&d);
        CHECK_EQ(parse_ng(pl.opt.source, &back, &d, NULL, NULL), 0);
        EquivResult er;
        CHECK_EQ(equiv_policies(&er, &pl.pol, &back), 0);
        CHECK_EQ(er.equivalent, 1);
        policy_free(&back);
        diag_free(&d);
    }
    pipeline_free(&pl);
    free(src);

    /* basic: R2 shadowed by R1 (conflicting); R1 removable only after R2. */
    src = load_example("firewall_basic.fw");
    pipeline_run(&pl, src, SYNTAX_FW, MIN_BY_ACTION, RUN_FULL);
    CHECK(pl.analysed);
    if (pl.analysed) {
        CHECK_EQ(report(&pl, "R2")->status, ST_SHADOWED);
        CHECK_EQ(report(&pl, "R1")->status, ST_OK);
        CHECK_EQ(pl.eq.equivalent, 1);
    }
    pipeline_free(&pl);
    free(src);
}

/*
 * test_scan_vs_equiv -- Differential test: scan-based redundancy vs. old
 * equiv_with-based redundancy on random policies (P1-a requirement).
 *
 * For each random policy of up to 8 rules over 2 fields, run both detectors
 * for every non-shadowed rule and assert they agree.
 */
void test_scan_vs_equiv(void) {
    Rng rng = {0x1234567890ABCDEFull};

    for (int trial = 0; trial < 500; trial++) {
        int nrules = 1 + (int)(rng_next(&rng) % 8);
        Policy p;
        policy_init(&p);
        str_copy(p.name, "rand", sizeof p.name);
        p.nfields = 2;
        for (int k = 0; k < 2; k++) {
            str_copy(p.fields[k].name, k == 0 ? "a" : "b", sizeof p.fields[k].name);
            p.fields[k].domain.lo = 0;
            p.fields[k].domain.hi = 99;
        }
        str_copy(p.actions[0], "ALLOW", NG_NAME_LEN);
        str_copy(p.actions[1], "DENY",  NG_NAME_LEN);
        p.nactions = 2;
        p.default_action = (int)(rng_next(&rng) % 2);
        p.rules = NULL;
        p.nrules = 0;
        for (int ri = 0; ri < nrules; ri++) {
            Rule r;
            memset(&r, 0, sizeof r);
            snprintf(r.id, sizeof r.id, "R%d", ri + 1);
            r.index = ri;
            r.action = (int)(rng_next(&rng) % 2);
            for (int k = 0; k < 2; k++) {
                uint32_t a = (uint32_t)(rng_next(&rng) % 100);
                uint32_t b = (uint32_t)(rng_next(&rng) % 100);
                if (a > b) { uint32_t t = a; a = b; b = t; }
                r.cond[k].lo = a;
                r.cond[k].hi = b;
            }
            policy_add_rule(&p, &r);
        }

        Partition pt;
        partition_build(&pt, &p);
        Compiled c;
        char msg[160];
        if (compile_policy(&c, &p, &pt, 1, msg, sizeof msg) != 0) {
            policy_free(&p); partition_free(&pt); compiled_free(&c);
            continue;
        }

        Analysis a;
        analysis_run(&a, &p, &pt, &c);

        for (int i = 0; i < p.nrules; i++) {
            if (a.r[i].status == ST_SHADOWED) continue;
            int scan_result = (a.r[i].status == ST_REDUNDANT) ? 1 : 0;
            int equiv_result = analysis_redundancy_equiv_check(&p, &pt, &c, i);
            if (equiv_result >= 0) {
                CHECK_EQ(scan_result, equiv_result);
            }
        }
        /* Optimizer: scan-based phase 2 vs the old equivalence-based phase 2. */
        Optimization o;
        optimize_run(&o, &p, SYNTAX_NG, &pt, &c, &a);
        unsigned char old_keep[NG_MAX_RULES];
        for (int i = 0; i < p.nrules; i++) old_keep[i] = a.r[i].status != ST_SHADOWED;
        if (optimize_keep_equiv(&p, &pt, &c, old_keep) == 0)
            for (int i = 0; i < p.nrules; i++) CHECK_EQ(o.keep[i], old_keep[i]);
        EquivResult er;
        CHECK_EQ(equiv_with(&er, &c.min, &o.optimized, &pt), 0);
        CHECK_EQ(er.equivalent, 1);
        optimize_free(&o);
        analysis_free(&a);
        compiled_free(&c);
        partition_free(&pt);
        policy_free(&p);
    }
}
