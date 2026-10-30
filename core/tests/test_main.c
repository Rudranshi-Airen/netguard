/*
 * test_main.c -- Runs every C test suite.  Usage: netguard_tests [EXAMPLES_DIR]
 */
#include "test.h"
#include "util.h"

#include <stdlib.h>

int g_checks = 0, g_failures = 0;
const char *g_examples_dir = "../examples";

char *load_example(const char *name) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", g_examples_dir, name);
    char *s = read_file(path);
    if (!s) {
        fprintf(stderr, "cannot read %s\n", path);
        exit(2);
    }
    return s;
}

int rule_index(const Policy *p, const char *id) {
    for (int i = 0; i < p->nrules; i++)
        if (strcmp(p->rules[i].id, id) == 0) return i;
    return -1;
}

static void run(const char *name, void (*fn)(void)) {
    int before = g_failures, checks = g_checks;
    fn();
    printf("  %-10s %4d checks  %s\n", name, g_checks - checks, g_failures == before ? "ok" : "FAILED");
}

int main(int argc, char **argv) {
    if (argc > 1) g_examples_dir = argv[1];
    printf("NetGuard C tests\n");
    run("lexer", test_lexer);
    run("parser", test_parser);
    run("partition", test_partition);
    run("automata", test_automata);
    run("analysis", test_analysis);
    run("scan_equiv", test_scan_vs_equiv);
    run("equiv", test_equiv);
    run("compare", test_compare);
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
