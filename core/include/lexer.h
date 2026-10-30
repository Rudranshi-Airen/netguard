/*
 * lexer.h -- Hand-written DFA scanner for the .fw firewall language, plus
 * the token log shared with the .ng front end (for the token table in the UI).
 */
#ifndef NG_LEXER_H
#define NG_LEXER_H

#include <stdint.h>
#include "diag.h"

typedef enum {
    TOK_ACTION, TOK_PROTO, TOK_FROM, TOK_TO, TOK_PORT, TOK_DEFAULT, TOK_ANY,
    TOK_IPV4, TOK_CIDR, TOK_INT, TOK_DASH, TOK_NEWLINE, TOK_EOF, TOK_ERROR
} TokType;

typedef struct {
    TokType  type;
    int      line, col;
    char     lexeme[64];
    uint64_t ival;          /* TOK_INT value (saturated at 99999999999) */
    uint32_t oct[4];        /* TOK_IPV4 / TOK_CIDR octets (saturated at 9999) */
    uint32_t prefix;        /* TOK_CIDR prefix length (saturated) */
} Token;

typedef struct { Token *v; int n, cap; } TokenVec;

/* Token record for JSON output; type is a printable name. */
typedef struct { char type[12]; int line, col; char lexeme[64]; } TokRec;
typedef struct { TokRec *v; int n, cap; } TokLog;

void tok_log_init(TokLog *l);
void tok_log_free(TokLog *l);
void tok_log_add(TokLog *l, const char *type, int line, int col, const char *lexeme);

const char *tok_type_name(TokType t);

/* Scan the whole source into toks (always ends with TOK_EOF).  Lexical
 * errors become TOK_ERROR tokens plus a diagnostic; scanning never stops. */
void lex_fw(const char *src, TokenVec *toks, DiagList *diags);
void tokvec_free(TokenVec *t);

#endif
