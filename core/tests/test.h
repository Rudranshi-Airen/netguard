/*
 * test.h -- A tiny assertion framework (no external libraries).
 *
 * CHECK(cond) records a failure with file:line and keeps going, so one run
 * reports every failing assertion.  CHECK_EQ prints both integer values.
 */
#ifndef NG_TEST_H
#define NG_TEST_H

#include <stdio.h>
#include <string.h>

extern int g_checks, g_failures;
extern const char *g_examples_dir;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        g_checks++;                                                                 \
        if (!(cond)) {                                                              \
            g_failures++;                                                           \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                           \
    } while (0)

#define CHECK_EQ(a, b)                                                              \
    do {                                                                            \
        long long a_ = (long long)(a), b_ = (long long)(b);                         \
        g_checks++;                                                                 \
        if (a_ != b_) {                                                             \
            g_failures++;                                                           \
            fprintf(stderr, "  FAIL %s:%d: %s == %s  (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, a_, b_); \
        }                                                                           \
    } while (0)

#define CHECK_STR(a, b)                                                             \
    do {                                                                            \
        const char *a_ = (a), *b_ = (b);                                            \
        g_checks++;                                                                 \
        if (strcmp(a_, b_) != 0) {                                                  \
            g_failures++;                                                           \
            fprintf(stderr, "  FAIL %s:%d: %s == \"%s\"  (got \"%s\")\n", __FILE__, __LINE__, #a, b_, a_); \
        }                                                                           \
    } while (0)

void test_lexer(void);
void test_parser(void);
void test_partition(void);
void test_automata(void);
void test_analysis(void);
void test_scan_vs_equiv(void);
void test_equiv(void);
void test_compare(void);

/* Helpers shared by the suites (test_main.c). */
#include "pipeline.h"
char *load_example(const char *name);          /* caller frees */
int   rule_index(const Policy *p, const char *id);

#endif
