/*
 * test_partition.c -- Interval partitioning (alphabet construction).
 */
#include "parser_fw.h"
#include "parser_ng.h"
#include "partition.h"
#include "test.h"

#include <stdlib.h>

static void check_invariants(const Policy *p, const Partition *pt) {
    for (int k = 0; k < p->nfields; k++) {
        const FieldPart *fp = &pt->f[k];
        CHECK_EQ(fp->iv[0].lo, p->fields[k].domain.lo);
        CHECK_EQ(fp->iv[fp->nsyms - 1].hi, p->fields[k].domain.hi);
        for (int j = 0; j < fp->nsyms; j++) {
            CHECK(fp->iv[j].lo <= fp->iv[j].hi);
            if (j > 0) CHECK_EQ((long long)fp->iv[j].lo, (long long)fp->iv[j - 1].hi + 1);   /* disjoint, gapless */
            CHECK_EQ(partition_lookup(pt, k, fp->iv[j].lo), j);
            CHECK_EQ(partition_lookup(pt, k, fp->iv[j].hi), j);
        }
        for (int i = 0; i < p->nrules; i++) {
            int a, b;
            CHECK_EQ(partition_span(pt, k, p->rules[i].cond[k], &a, &b), 0);   /* exact union */
        }
        /* minimality: adjacent intervals are covered by different rule sets */
        for (int j = 1; j < fp->nsyms; j++) {
            int differ = 0;
            for (int i = 0; i < p->nrules; i++) {
                Range c = p->rules[i].cond[k];
                int in1 = c.lo <= fp->iv[j - 1].lo && fp->iv[j - 1].hi <= c.hi;
                int in2 = c.lo <= fp->iv[j].lo && fp->iv[j].hi <= c.hi;
                if (in1 != in2) differ = 1;
            }
            CHECK(differ);
        }
    }
}

void test_partition(void) {
    Policy p;
    DiagList d;
    Partition pt;

    /* overlapping [10,20] [15,30], adjacent [31,40], single point [50,50], full domain */
    diag_init(&d);
    parse_ng("ruleset t; field x : 0 .. 100; field y : 0 .. 9; default N;\n"
             "rule a : A when x in 10 .. 20;\n"
             "rule b : A when x in 15 .. 30;\n"
             "rule c : A when x in 31 .. 40;\n"
             "rule e : A when x == 50;\n"
             "rule f : A when x in 0 .. 100 and y in 0 .. 9;\n",
             &p, &d, NULL, NULL);
    CHECK_EQ(diag_errors(&d), 0);
    partition_build(&pt, &p);
    /* cuts: 0 10 15 21 31 41 50 51 101 -> 8 intervals on x; y untouched -> 1 */
    CHECK_EQ(pt.f[0].nsyms, 8);
    CHECK_EQ(pt.f[1].nsyms, 1);
    CHECK_EQ(pt.cells, 8);
    CHECK_EQ(pt.total_syms, 9);
    CHECK_EQ(pt.f[0].iv[1].lo, 10);
    CHECK_EQ(pt.f[0].iv[1].hi, 14);
    CHECK_EQ(pt.f[0].iv[2].lo, 15);
    CHECK_EQ(pt.f[0].iv[2].hi, 20);
    CHECK_EQ(pt.f[0].iv[6].lo, 50);
    CHECK_EQ(pt.f[0].iv[6].hi, 50);
    CHECK_EQ(partition_lookup(&pt, 0, 9), 0);
    CHECK_EQ(partition_lookup(&pt, 0, 100), 7);
    CHECK_EQ(partition_lookup(&pt, 0, 101), -1);
    check_invariants(&p, &pt);
    int a, b;
    CHECK_EQ(partition_span(&pt, 0, (Range){10, 30}, &a, &b), 0);
    CHECK_EQ(a, 1);
    CHECK_EQ(b, 3);
    CHECK(partition_span(&pt, 0, (Range){11, 30}, &a, &b) != 0);      /* not a union of whole intervals */
    partition_free(&pt);
    policy_free(&p);
    diag_free(&d);

    /* Full 32-bit domain: hi + 1 = 2^32 must not overflow. */
    char *src = load_example("firewall_anomalies.fw");
    diag_init(&d);
    CHECK_EQ(parse_fw(src, &p, &d, NULL, NULL), 0);
    partition_build(&pt, &p);
    CHECK_EQ(pt.f[1].iv[pt.f[1].nsyms - 1].hi, 0xFFFFFFFFu);
    CHECK_EQ(pt.f[0].nsyms, 7);    /* proto: 0 1 2-5 6 7-16 17 18-255 */
    CHECK_EQ(pt.cells, (unsigned long long)pt.f[0].nsyms * pt.f[1].nsyms * pt.f[2].nsyms * pt.f[3].nsyms);
    check_invariants(&p, &pt);
    partition_free(&pt);
    policy_free(&p);
    diag_free(&d);
    free(src);

    /* No rules: one interval per field. */
    diag_init(&d);
    parse_fw("DEFAULT ALLOW\n", &p, &d, NULL, NULL);
    partition_build(&pt, &p);
    for (int k = 0; k < 4; k++) CHECK_EQ(pt.f[k].nsyms, 1);
    CHECK_EQ(pt.cells, 1);
    partition_free(&pt);
    policy_free(&p);
    diag_free(&d);
}
