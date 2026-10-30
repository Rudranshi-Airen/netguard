/*
 * test_equiv.c -- Product-automaton equivalence and counterexamples.
 */
#include "compare.h"
#include "oracle.h"
#include "parser_fw.h"
#include "test.h"

#include <stdlib.h>

static void parse(const char *src, Policy *p) {
    DiagList d;
    diag_init(&d);
    CHECK_EQ(parse_fw(src, p, &d, NULL, NULL), 0);
    diag_free(&d);
}

static void expect_equiv(const char *a, const char *b, int equivalent) {
    Policy pa, pb;
    parse(a, &pa);
    parse(b, &pb);
    EquivResult er;
    CHECK_EQ(equiv_policies(&er, &pa, &pb), 0);
    CHECK_EQ(er.equivalent, equivalent);
    CHECK_EQ(er.has_counterexample, !equivalent);
    if (!equivalent) {
        /* The counterexample really separates the two policies (independent oracle). */
        int oa = oracle_eval(&pa, er.packet, NULL), ob = oracle_eval(&pb, er.packet, NULL);
        CHECK(oa != ob);
        CHECK_EQ(oa, er.action_a);
        CHECK_EQ(ob, er.action_b);
    }
    policy_free(&pa);
    policy_free(&pb);
}

void test_equiv(void) {
    /* A DENY rule under DEFAULT DENY is equivalent to nothing at all. */
    expect_equiv("DENY TCP FROM ANY TO ANY PORT 22\nDEFAULT DENY", "DEFAULT DENY", 1);
    /* Adjacent ranges vs their union. */
    expect_equiv("ALLOW TCP FROM ANY TO ANY PORT 80-89\nALLOW TCP FROM ANY TO ANY PORT 90-100",
                 "ALLOW TCP FROM ANY TO ANY PORT 80-100", 1);
    /* Swapping disjoint rules preserves behaviour. */
    expect_equiv("ALLOW TCP FROM ANY TO ANY PORT 80\nDENY UDP FROM ANY TO ANY PORT 80",
                 "DENY UDP FROM ANY TO ANY PORT 80\nALLOW TCP FROM ANY TO ANY PORT 80", 1);
    /* CIDR split in halves. */
    expect_equiv("ALLOW ANY FROM 10.0.0.0/8 TO ANY",
                 "ALLOW ANY FROM 10.0.0.0/9 TO ANY\nALLOW ANY FROM 10.128.0.0/9 TO ANY", 1);

    /* Not equivalent: swapping overlapping rules with different actions. */
    expect_equiv("DENY TCP FROM ANY TO ANY PORT 22\nALLOW TCP FROM 10.0.0.0/8 TO ANY PORT 22",
                 "ALLOW TCP FROM 10.0.0.0/8 TO ANY PORT 22\nDENY TCP FROM ANY TO ANY PORT 22", 0);
    /* Not equivalent: different default. */
    expect_equiv("ALLOW TCP FROM ANY TO ANY PORT 443\nDEFAULT DENY",
                 "ALLOW TCP FROM ANY TO ANY PORT 443\nDEFAULT ALLOW", 0);
    /* Not equivalent: an off-by-one port range. */
    expect_equiv("ALLOW TCP FROM ANY TO ANY PORT 80-100", "ALLOW TCP FROM ANY TO ANY PORT 80-99", 0);

    /* Counterexample content for the off-by-one case: port 100, TCP. */
    Policy a, b;
    parse("ALLOW TCP FROM ANY TO ANY PORT 80-100", &a);
    parse("ALLOW TCP FROM ANY TO ANY PORT 80-99", &b);
    EquivResult er;
    equiv_policies(&er, &a, &b);
    CHECK_EQ(er.packet[0], 6);
    CHECK_EQ(er.packet[3], 100);
    CHECK_STR(a.actions[er.action_a], "ALLOW");
    CHECK_STR(a.actions[er.action_b], "DENY");
    policy_free(&a);
    policy_free(&b);

    /* Removing R1 alone from the basic policy is NOT equivalent. */
    char *src = load_example("firewall_basic.fw");
    parse(src, &a);
    unsigned char keep[4] = {0, 1, 1, 1};
    policy_subset(&b, &a, keep);
    CHECK_EQ(equiv_policies(&er, &a, &b), 0);
    CHECK_EQ(er.equivalent, 0);
    CHECK(oracle_eval(&a, er.packet, NULL) != oracle_eval(&b, er.packet, NULL));
    policy_free(&a);
    policy_free(&b);
    free(src);
}

/* The `netguard equiv` command (compare.c): equivalent, non-equivalent,
 * parse error, action order differing between .ng files, field mismatch. */
void test_compare(void) {
    Compare c;
    const char *orig = "DENY TCP FROM ANY TO ANY PORT 22\nALLOW TCP FROM ANY TO ANY PORT 80-89\n"
                       "ALLOW TCP FROM ANY TO ANY PORT 90-100\nDEFAULT DENY\n";

    CHECK_EQ(compare_sources(&c, orig, "ALLOW TCP FROM ANY TO ANY PORT 80-100\nDEFAULT DENY\n", SYNTAX_FW), 0);
    CHECK(c.compared);
    CHECK_EQ(c.er.equivalent, 1);
    CHECK_EQ(c.a.nrules, 3);
    CHECK_EQ(c.b.nrules, 1);
    compare_free(&c);

    CHECK_EQ(compare_sources(&c, orig, "ALLOW TCP FROM ANY TO ANY PORT 80-101\nDEFAULT DENY\n", SYNTAX_FW), 0);
    CHECK_EQ(c.er.equivalent, 0);
    CHECK_EQ(c.er.packet[3], 101);
    CHECK(oracle_eval(&c.a, c.er.packet, NULL) != oracle_eval(&c.b, c.er.packet, NULL));
    CHECK_STR(c.a.actions[c.er.action_a], "DENY");
    CHECK_STR(c.a.actions[c.er.action_b], "ALLOW");
    CHECK_EQ(c.winner_a, -1);
    CHECK_EQ(c.winner_b, 0);
    compare_free(&c);

    CHECK_EQ(compare_sources(&c, orig, "ALLOW TCP FROM ANY TO ANY PORT 80-100\nPERMIT UDP FROM ANY TO ANY\n", SYNTAX_FW), 1);
    CHECK(!c.compared);
    CHECK(!c.parsed_b);
    CHECK_EQ(c.diag_b.count, 1);
    CHECK_EQ(c.diag_b.items[0].line, 2);
    CHECK_EQ(c.diag_b.items[0].col, 1);
    compare_free(&c);

    /* Same decisions, actions first mentioned in a different order. */
    const char *ng_a = "ruleset t; field x : 0 .. 9; default C; rule r1 : A when x in 0 .. 3; rule r2 : B when x in 4 .. 6;";
    const char *ng_b = "ruleset t; field x : 0 .. 9; default C; rule q : B when x in 4 .. 6; rule p : A when x in 0 .. 3;";
    CHECK_EQ(compare_sources(&c, ng_a, ng_b, SYNTAX_NG), 0);
    CHECK_EQ(c.er.equivalent, 1);
    compare_free(&c);
    const char *ng_c = "ruleset t; field x : 0 .. 9; default C; rule q : B when x in 3 .. 6; rule p : A when x in 0 .. 3;";
    CHECK_EQ(compare_sources(&c, ng_a, ng_c, SYNTAX_NG), 0);
    CHECK_EQ(c.er.equivalent, 0);
    CHECK_EQ(c.er.packet[0], 3);
    compare_free(&c);

    CHECK_EQ(compare_sources(&c, ng_a, "ruleset t; field y : 0 .. 9; default C;", SYNTAX_NG), 1);
    CHECK(strstr(c.error, "differs") != NULL);
    compare_free(&c);
}
