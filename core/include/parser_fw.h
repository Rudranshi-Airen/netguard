/*
 * parser_fw.h -- Recursive-descent parser for the .fw firewall language.
 */
#ifndef NG_PARSER_FW_H
#define NG_PARSER_FW_H

#include "diag.h"
#include "ir.h"
#include "lexer.h"

/* Lex + parse + semantic-check `src`.  The policy receives every valid
 * rule; all errors are in diags.  Tokens are appended to log (may be NULL).
 * Returns the number of errors. */
int parse_fw(const char *src, Policy *out, DiagList *diags, TokLog *log, double *lex_ms);

#endif
