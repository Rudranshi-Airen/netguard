/*
 * test_parser.c -- Both front ends: valid forms, each error, multi-error recovery.
 */
#include "parser_fw.h"
#include "parser_ng.h"
#include "test.h"

#include <stdlib.h>

static int parse(const char *src, Policy *p, DiagList *d) {
    diag_init(d);
    return parse_fw(src, p, d, NULL, NULL);
}

static int has_diag(const DiagList *d, DiagLevel lvl, int line, const char *needle) {
    for (int i = 0; i < d->count; i++)
        if (d->items[i].level == lvl && d->items[i].line == line && strstr(d->items[i].message, needle)) return 1;
    return 0;
}

static void expect_single_error(const char *src, const char *needle) {
    Policy p;
    DiagList d;
    int errs = parse(src, &p, &d);
    CHECK_EQ(errs, 1);
    CHECK(has_diag(&d, DIAG_ERROR, 1, needle));
    policy_free(&p);
    diag_free(&d);
}

void test_parser(void) {
    Policy p;
    DiagList d;

    /* Every valid form of proto, addr and portspec. */
    const char *ok_src =
        "ALLOW TCP FROM ANY TO ANY\n"
        "DENY UDP FROM 10.0.0.1 TO 10.0.0.0/8 PORT 53\n"
        "ALLOW ICMP FROM 1.1.1.1-1.1.1.9 TO ANY\n"
        "DENY ANY FROM ANY TO ANY PORT ANY\n"
        "ALLOW 47 FROM ANY TO ANY PORT 1000-2000\n"
        "\n# comment only\n"
        "DEFAULT ALLOW\n";
    CHECK_EQ(parse(ok_src, &p, &d), 0);
    CHECK_EQ(d.count, 0);
    CHECK_EQ(p.nrules, 5);
    CHECK_STR(p.rules[0].id, "R1");
    CHECK_EQ(p.rules[0].cond[0].lo, 6);
    CHECK_EQ(p.rules[0].cond[3].hi, 65535);
    CHECK_EQ(p.rules[1].cond[0].lo, 17);
    CHECK_EQ(p.rules[1].cond[1].lo, 0x0A000001u);
    CHECK_EQ(p.rules[1].cond[1].hi, 0x0A000001u);
    CHECK_EQ(p.rules[1].cond[2].lo, 0x0A000000u);
    CHECK_EQ(p.rules[1].cond[2].hi, 0x0AFFFFFFu);
    CHECK_EQ(p.rules[1].cond[3].lo, 53);
    CHECK_EQ(p.rules[2].cond[0].lo, 1);
    CHECK_EQ(p.rules[2].cond[1].lo, 0x01010101u);
    CHECK_EQ(p.rules[2].cond[1].hi, 0x01010109u);
    CHECK_EQ(p.rules[3].cond[0].lo, 0);
    CHECK_EQ(p.rules[3].cond[0].hi, 255);
    CHECK_EQ(p.rules[4].cond[0].lo, 47);
    CHECK_EQ(p.rules[4].cond[3].lo, 1000);
    CHECK_EQ(p.rules[4].cond[3].hi, 2000);
    CHECK_STR(p.actions[p.default_action], "ALLOW");
    CHECK_STR(p.rules[1].text, "DENY UDP FROM 10.0.0.1 TO 10.0.0.0/8 PORT 53");
    policy_free(&p);
    diag_free(&d);

    /* DEFAULT is optional and defaults to DENY. */
    CHECK_EQ(parse("ALLOW TCP FROM ANY TO ANY PORT 80", &p, &d), 0);
    CHECK_STR(p.actions[p.default_action], "DENY");
    policy_free(&p);
    diag_free(&d);

    /* Each semantic / syntax / lexical error on its own. */
    expect_single_error("ALLOW TCP FROM 300.0.0.1 TO ANY", "greater than 255");
    expect_single_error("ALLOW TCP FROM 10.0.0.0/33 TO ANY", "greater than 32");
    expect_single_error("ALLOW TCP FROM ANY TO ANY PORT 90-80", "empty");
    expect_single_error("ALLOW TCP FROM ANY TO ANY PORT 70000", "out of range");
    expect_single_error("ALLOW TCP FROM 10.0.0.9-10.0.0.1 TO ANY", "empty");
    expect_single_error("ALLOW 300 FROM ANY TO ANY", "protocol number");
    expect_single_error("PERMIT TCP FROM ANY TO ANY", "unknown word");
    expect_single_error("ALLOW TCP FROM ANY PORT 22", "expected TO");
    expect_single_error("ALLOW TCP ANY TO ANY", "expected FROM");
    expect_single_error("ALLOW TCP FROM ANY TO ANY PORT", "expected a port");
    expect_single_error("ALLOW TCP FROM ANY TO ANY PORT 80 443", "expected end of line");

    /* Warnings: host bits normalised; PORT ignored for ICMP. */
    CHECK_EQ(parse("ALLOW TCP FROM 10.1.2.3/8 TO ANY\nDENY ICMP FROM ANY TO ANY PORT 7", &p, &d), 0);
    CHECK(has_diag(&d, DIAG_WARNING, 1, "host bits"));
    CHECK(has_diag(&d, DIAG_WARNING, 2, "ignored"));
    CHECK_EQ(p.rules[0].cond[1].lo, 0x0A000000u);
    CHECK_EQ(p.rules[0].cond[1].hi, 0x0AFFFFFFu);
    CHECK_EQ(p.rules[1].cond[3].lo, 0);
    CHECK_EQ(p.rules[1].cond[3].hi, 65535);
    policy_free(&p);
    diag_free(&d);

    /* Duplicate DEFAULT */
    CHECK_EQ(parse("DEFAULT DENY\nDEFAULT ALLOW", &p, &d), 1);
    CHECK(has_diag(&d, DIAG_ERROR, 2, "duplicate DEFAULT"));
    policy_free(&p);
    diag_free(&d);

    /* Multi-error recovery: every error in errors.fw is reported. */
    char *src = load_example("errors.fw");
    int errs = parse(src, &p, &d);
    int err_lines[] = {2, 3, 5, 6, 7, 8, 9, 10, 12, 14};
    CHECK_EQ(errs, 10);
    for (size_t i = 0; i < sizeof err_lines / sizeof err_lines[0]; i++) {
        int found = 0;
        for (int k = 0; k < d.count; k++)
            if (d.items[k].level == DIAG_ERROR && d.items[k].line == err_lines[i]) found = 1;
        CHECK(found);
    }
    CHECK(has_diag(&d, DIAG_WARNING, 4, "host bits"));
    CHECK(has_diag(&d, DIAG_WARNING, 11, "ignored"));
    for (int k = 1; k < d.count; k++) CHECK(d.items[k - 1].line <= d.items[k].line);   /* sorted */
    free(src);
    policy_free(&p);
    diag_free(&d);

    /* .ng front end: same IR. */
    src = load_example("tax.ng");
    diag_init(&d);
    CHECK_EQ(parse_ng(src, &p, &d, NULL, NULL), 0);
    CHECK_STR(p.name, "tax");
    CHECK_EQ(p.nfields, 2);
    CHECK_EQ(p.nrules, 5);
    CHECK_EQ(p.fields[0].domain.hi, 100000000);
    CHECK_STR(p.actions[p.default_action], "SLAB_30");
    CHECK_STR(p.rules[1].id, "t2");
    CHECK_EQ(p.rules[1].cond[1].lo, 80);
    CHECK_EQ(p.rules[0].cond[1].lo, 0);          /* unmentioned field: whole domain */
    CHECK_EQ(p.rules[0].cond[1].hi, 150);
    free(src);
    policy_free(&p);
    diag_free(&d);

    /* .ng errors, all collected. */
    diag_init(&d);
    const char *bad_ng =
        "ruleset x;\n"
        "field a : 0 .. 10;\n"
        "field a : 0 .. 5;\n"                 /* duplicate field */
        "field b : 9 .. 3;\n"                 /* empty domain */
        "default NO;\n"
        "rule r1 : YES when c in 0 .. 1;\n"   /* unknown field */
        "rule r2 : YES when a in 0 .. 99;\n"  /* outside domain */
        "rule r3 : YES when a == 3 and a == 4;\n" /* empty intersection */
        "rule r4 YES when a == 1;\n"          /* syntax: missing ':' */
        "rule r5 : YES when a == 2;\n";
    int nerr = parse_ng(bad_ng, &p, &d, NULL, NULL);
    CHECK_EQ(nerr, 6);
    CHECK_EQ(p.nrules, 1);
    CHECK_STR(p.rules[0].id, "r5");
    policy_free(&p);
    diag_free(&d);
}
