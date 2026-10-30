/*
 * compare.h -- `netguard equiv`: prove two policy sources equivalent or
 * produce a counterexample packet.
 */
#ifndef NG_COMPARE_H
#define NG_COMPARE_H

#include "diag.h"
#include "equiv.h"
#include "ir.h"
#include "json.h"

typedef struct {
    Syntax      syntax;
    DiagList    diag_a, diag_b;   /* diagnostics of the original / suggested source */
    Policy      a, b;             /* b's actions are remapped onto a's action table */
    int         parsed_a, parsed_b;
    int         compared;         /* the equivalence check ran */
    char        error[256];       /* why it could not run (other than parse errors) */
    EquivResult er;
    int         winner_a, winner_b;   /* rules deciding the counterexample (-1 = DEFAULT) */
} Compare;

/* Returns 0 if the check ran, 1 if a source has errors / the policies are
 * not comparable, -1 on size limits. */
int  compare_sources(Compare *c, const char *src_a, const char *src_b, Syntax syn);
void compare_free(Compare *c);
void emit_compare_json(Json *j, const Compare *c);

#endif
