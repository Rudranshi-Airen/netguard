/*
 * pipeline.h -- The compiler driver: runs the phases in order and
 * serializes their results.
 */
#ifndef NG_PIPELINE_H
#define NG_PIPELINE_H

#include "analysis.h"
#include "classify.h"
#include "diag.h"
#include "equiv.h"
#include "ir.h"
#include "json.h"
#include "lexer.h"
#include "minimize.h"
#include "optimize.h"
#include "partition.h"

enum { PH_LEX, PH_PARSE, PH_PARTITION, PH_NFA, PH_DFA, PH_MINIMIZE, PH_ANALYSIS, PH_OPTIMIZE,
       PH_EQUIV, PH_DOT, PH_TOTAL, PH_COUNT };

typedef enum { RUN_FRONT = 0, RUN_AUTOMATA = 1, RUN_FULL = 2 } RunLevel;

typedef struct {
    Syntax    syntax;
    MinMode   min_mode;
    DiagList  diags;
    TokLog    toks;
    Policy    pol;
    int       ok;              /* no errors */
    int       built;           /* partition + automata are valid */
    int       analysed;        /* analysis + optimization + equivalence are valid */
    Partition pt;
    Compiled  c;               /* NFA, DFA, action-minimized DFA */
    DFA       min_rule;        /* rule-minimized DFA */
    Analysis  an;
    Optimization opt;
    EquivResult eq;
    double    ms[PH_COUNT];
} Pipeline;

int  pipeline_run(Pipeline *pl, const char *src, Syntax syn, MinMode mode, RunLevel level);
void pipeline_free(Pipeline *pl);

/* JSON emitters (the documents printed by the CLI). */
void emit_compile_json(Json *j, Pipeline *pl);
void emit_classify_json(Json *j, const Pipeline *pl, const uint32_t *vals, const char *text);
void emit_error_json(Json *j, const char *msg);
/* Random differential verification. */
void emit_verify_json(Json *j, const Pipeline *pl, long n, uint64_t seed);

#endif
