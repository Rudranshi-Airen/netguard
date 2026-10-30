/*
 * lexer.c -- Hand-written DFA scanner for the .fw firewall policy language.
 *
 * Algorithm.  The scanner is an explicit deterministic finite automaton: a
 * loop whose body is `switch (state)`, and inside each state a decision on
 * the class of the current character (digit, letter, '.', '/', '-', '#',
 * blank, newline, EOF, other).  Each transition either consumes the
 * character and moves to another state, or stops and emits a token for the
 * lexeme scanned so far (longest match).  The automaton recognises:
 *
 *     WORD  = letter (letter|digit|_)*          -> keyword lookup
 *     INT   = digit+
 *     IPV4  = INT '.' INT '.' INT '.' INT
 *     CIDR  = IPV4 '/' INT
 *     DASH  = '-'          NEWLINE = '\n'        comments '#' ... end of line
 *
 * IPv4 and CIDR literals are recognised here, inside the scanner, not by
 * the parser.  Keywords are case-insensitive (the WORD lexeme is looked up
 * in a keyword table, as flex-generated scanners usually do).  Malformed
 * lexemes go to the BAD state, which consumes up to the next delimiter and
 * emits one ERROR token with a diagnostic -- so scanning always continues
 * and every lexical error in the file is reported.
 *
 * Complexity: O(n) time in the input length; each character is examined
 * once (keyword lookup is O(1) per word, the table is constant-sized).
 *
 * Compiler-design concept: lexical analysis by a hand-coded DFA, character
 * classes, maximal munch, and error tokens for error recovery.
 */
#include "lexer.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- token log (shared with the .ng front end) ---- */

void tok_log_init(TokLog *l) { l->v = NULL; l->n = l->cap = 0; }
void tok_log_free(TokLog *l) { free(l->v); tok_log_init(l); }

void tok_log_add(TokLog *l, const char *type, int line, int col, const char *lexeme) {
    if (l->n == l->cap) {
        l->cap = l->cap ? l->cap * 2 : 64;
        l->v = xrealloc(l->v, sizeof(TokRec) * (size_t)l->cap);
    }
    TokRec *t = &l->v[l->n++];
    str_copy(t->type, type, sizeof t->type);
    t->line = line;
    t->col = col;
    str_copy(t->lexeme, lexeme, sizeof t->lexeme);
}

const char *tok_type_name(TokType t) {
    static const char *names[] = {"ACTION", "PROTO", "FROM", "TO", "PORT", "DEFAULT", "ANY",
                                  "IPV4", "CIDR", "INT", "DASH", "NEWLINE", "EOF", "ERROR"};
    return names[t];
}

void tokvec_free(TokenVec *t) { free(t->v); t->v = NULL; t->n = t->cap = 0; }

/* ---- the scanner ---- */

typedef enum {
    CC_DIGIT, CC_ALPHA, CC_DOT, CC_SLASH, CC_DASH, CC_HASH, CC_BLANK, CC_NL, CC_EOF, CC_OTHER
} CharClass;

typedef enum {
    S_START,     /* between tokens */
    S_COMMENT,   /* after '#', until newline */
    S_WORD,      /* letters/digits/_ */
    S_INT,       /* digits; may become the first octet of an IPv4 */
    S_IP_DOT,    /* just read a '.', expecting an octet */
    S_IP_OCTET,  /* reading octet 2..4 */
    S_SLASH,     /* read IPV4 '/', expecting prefix digits */
    S_PREFIX,    /* reading the CIDR prefix */
    S_BAD        /* malformed lexeme: skip to the next delimiter */
} LexState;

static CharClass classify(int c) {
    if (c < 0) return CC_EOF;
    if (c >= '0' && c <= '9') return CC_DIGIT;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') return CC_ALPHA;
    switch (c) {
    case '.': return CC_DOT;
    case '/': return CC_SLASH;
    case '-': return CC_DASH;
    case '#': return CC_HASH;
    case ' ': case '\t': case '\r': case '\f': case '\v': return CC_BLANK;
    case '\n': return CC_NL;
    default: return CC_OTHER;
    }
}

/* Characters that end a token without being part of it. */
static int is_delim(CharClass cc) {
    return cc == CC_BLANK || cc == CC_NL || cc == CC_EOF || cc == CC_HASH || cc == CC_DASH;
}

static const struct { const char *word; TokType type; } KEYWORDS[] = {
    {"ALLOW", TOK_ACTION}, {"DENY", TOK_ACTION}, {"TCP", TOK_PROTO}, {"UDP", TOK_PROTO},
    {"ICMP", TOK_PROTO},   {"ANY", TOK_ANY},     {"FROM", TOK_FROM}, {"TO", TOK_TO},
    {"PORT", TOK_PORT},    {"DEFAULT", TOK_DEFAULT},
};
#define NKEYWORDS ((int)(sizeof KEYWORDS / sizeof KEYWORDS[0]))

typedef struct {
    const char *src;
    size_t pos;
    int line, col;
    TokenVec *out;
    DiagList *diags;
} Scanner;

static void emit(Scanner *s, const Token *t) {
    TokenVec *v = s->out;
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 128;
        v->v = xrealloc(v->v, sizeof(Token) * (size_t)v->cap);
    }
    v->v[v->n++] = *t;
}

static void set_lexeme(Token *t, const char *src, size_t from, size_t to) {
    size_t n = to - from;
    if (n >= sizeof t->lexeme) n = sizeof t->lexeme - 1;
    memcpy(t->lexeme, src + from, n);
    t->lexeme[n] = '\0';
}

static void suggest_keyword(const char *word, char *hint, size_t cap) {
    static const struct { const char *alias, *kw; } ALIASES[] = {
        {"PERMIT", "ALLOW"}, {"ACCEPT", "ALLOW"}, {"PASS", "ALLOW"},
        {"DROP", "DENY"},    {"REJECT", "DENY"},  {"BLOCK", "DENY"},
    };
    for (size_t i = 0; i < sizeof ALIASES / sizeof ALIASES[0]; i++)
        if (str_ieq(word, ALIASES[i].alias)) {
            snprintf(hint, cap, "use '%s' (the language's keyword for this action)", ALIASES[i].kw);
            return;
        }
    int best = 99, bi = -1;
    for (int i = 0; i < NKEYWORDS; i++) {
        int d = edit_distance(word, KEYWORDS[i].word);
        if (d < best) { best = d; bi = i; }
    }
    if (bi >= 0 && best <= 2)
        snprintf(hint, cap, "did you mean '%s'?", KEYWORDS[bi].word);
    else
        snprintf(hint, cap, "keywords are ALLOW DENY TCP UDP ICMP ANY FROM TO PORT DEFAULT");
}

void lex_fw(const char *src, TokenVec *toks, DiagList *diags) {
    Scanner s = {src, 0, 1, 1, toks, diags};
    LexState state = S_START;
    Token tok;
    size_t start = 0;
    int octets = 0;              /* octets read so far in an IPv4 literal */
    const char *bad_what = "";   /* what the BAD lexeme was trying to be */

    memset(&tok, 0, sizeof tok);
    for (;;) {
        int c = src[s.pos] ? (unsigned char)src[s.pos] : -1;
        CharClass cc = classify(c);
        int consume = 1;         /* advance past c at the bottom of the loop */

        switch (state) {
        case S_START:
            memset(&tok, 0, sizeof tok);
            tok.line = s.line;
            tok.col = s.col;
            start = s.pos;
            switch (cc) {
            case CC_BLANK: break;
            case CC_NL:
                tok.type = TOK_NEWLINE;
                str_copy(tok.lexeme, "\\n", sizeof tok.lexeme);
                emit(&s, &tok);
                break;
            case CC_EOF:
                tok.type = TOK_EOF;
                emit(&s, &tok);
                return;
            case CC_HASH: state = S_COMMENT; break;
            case CC_DASH:
                tok.type = TOK_DASH;
                str_copy(tok.lexeme, "-", sizeof tok.lexeme);
                emit(&s, &tok);
                break;
            case CC_DIGIT:
                tok.ival = (uint64_t)(c - '0');
                state = S_INT;
                break;
            case CC_ALPHA: state = S_WORD; break;
            default:
                bad_what = "character";
                state = S_BAD;
                break;
            }
            break;

        case S_COMMENT:
            if (cc == CC_NL || cc == CC_EOF) { state = S_START; consume = 0; }
            break;

        case S_WORD:
            if (cc == CC_ALPHA || cc == CC_DIGIT) break;
            consume = 0;
            set_lexeme(&tok, src, start, s.pos);
            tok.type = TOK_ERROR;
            for (int i = 0; i < NKEYWORDS; i++)
                if (str_ieq(tok.lexeme, KEYWORDS[i].word)) { tok.type = KEYWORDS[i].type; break; }
            if (tok.type == TOK_ERROR) {
                char hint[160];
                suggest_keyword(tok.lexeme, hint, sizeof hint);
                diag_add(diags, DIAG_ERROR, tok.line, tok.col, "lexer", hint,
                         "unknown word '%s'", tok.lexeme);
            }
            emit(&s, &tok);
            state = S_START;
            break;

        case S_INT:
            if (cc == CC_DIGIT) {
                if (tok.ival < 99999999999ull) tok.ival = tok.ival * 10 + (uint64_t)(c - '0');
                break;
            }
            if (cc == CC_DOT) {
                tok.oct[0] = tok.ival > 9999 ? 9999 : (uint32_t)tok.ival;
                octets = 1;
                state = S_IP_DOT;
                break;
            }
            if (is_delim(cc)) {
                consume = 0;
                set_lexeme(&tok, src, start, s.pos);
                tok.type = TOK_INT;
                emit(&s, &tok);
                state = S_START;
                break;
            }
            bad_what = "number";
            state = S_BAD;
            break;

        case S_IP_DOT:
            if (cc == CC_DIGIT) {
                tok.oct[octets] = (uint32_t)(c - '0');
                octets++;
                state = S_IP_OCTET;
                break;
            }
            bad_what = "IPv4 address";
            consume = 0;
            state = S_BAD;
            break;

        case S_IP_OCTET:
            if (cc == CC_DIGIT) {
                uint32_t *o = &tok.oct[octets - 1];
                if (*o < 9999) *o = *o * 10 + (uint32_t)(c - '0');
                break;
            }
            if (cc == CC_DOT && octets < 4) { state = S_IP_DOT; break; }
            if (cc == CC_SLASH && octets == 4) { state = S_SLASH; break; }
            if (is_delim(cc) && octets == 4) {
                consume = 0;
                set_lexeme(&tok, src, start, s.pos);
                tok.type = TOK_IPV4;
                emit(&s, &tok);
                state = S_START;
                break;
            }
            bad_what = "IPv4 address";
            consume = 0;
            state = S_BAD;
            break;

        case S_SLASH:
            if (cc == CC_DIGIT) {
                tok.prefix = (uint32_t)(c - '0');
                state = S_PREFIX;
                break;
            }
            bad_what = "CIDR block (missing prefix length)";
            consume = 0;
            state = S_BAD;
            break;

        case S_PREFIX:
            if (cc == CC_DIGIT) {
                if (tok.prefix < 9999) tok.prefix = tok.prefix * 10 + (uint32_t)(c - '0');
                break;
            }
            if (is_delim(cc)) {
                consume = 0;
                set_lexeme(&tok, src, start, s.pos);
                tok.type = TOK_CIDR;
                emit(&s, &tok);
                state = S_START;
                break;
            }
            bad_what = "CIDR block";
            consume = 0;
            state = S_BAD;
            break;

        case S_BAD:
            /* Always consume at least the character that caused the error. */
            if (is_delim(cc) && s.pos > start) {
                consume = 0;
                set_lexeme(&tok, src, start, s.pos);
                tok.type = TOK_ERROR;
                if (strcmp(bad_what, "character") == 0)
                    diag_add(diags, DIAG_ERROR, tok.line, tok.col, "lexer",
                             "remove it; words, numbers, IPv4 addresses and CIDR blocks are the only tokens",
                             "unexpected character '%c' in '%s'", tok.lexeme[0], tok.lexeme);
                else
                    diag_add(diags, DIAG_ERROR, tok.line, tok.col, "lexer",
                             "write a number, an IPv4 address (a.b.c.d) or a CIDR block (a.b.c.d/n)",
                             "malformed %s '%s'", bad_what, tok.lexeme);
                emit(&s, &tok);
                state = S_START;
            }
            break;
        }

        if (consume && cc != CC_EOF) {
            if (c == '\n') { s.line++; s.col = 1; }
            else s.col++;
            s.pos++;
        }
    }
}
