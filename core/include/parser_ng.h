/*
 * parser_ng.h -- Recursive-descent parser for the generic .ng rule language.
 * Produces the same Policy IR as the .fw front end.
 */
#ifndef NG_PARSER_NG_H
#define NG_PARSER_NG_H

#include "diag.h"
#include "ir.h"
#include "lexer.h"

/* Returns the number of errors; all diagnostics are in diags. */
int parse_ng(const char *src, Policy *out, DiagList *diags, TokLog *log, double *lex_ms);

#endif
