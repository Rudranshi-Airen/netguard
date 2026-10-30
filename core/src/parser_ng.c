/*
 * parser_ng.c -- Front end for the generic .ng rule language.
 *
 * It shows that the back end is domain-agnostic: this second, independent
 * front end lowers a different surface language to the very same IR.
 *
 * Scanner: a small hand-written scanner (switch on the character class)
 * producing IDENT, INT, KEYWORD, ':', ';', '..', '==', EOF and ERROR
 * tokens; comments run from '#' or '//' to the end of the line.
 *
 * Grammar (recursive descent, one function per non-terminal):
 *
 *   program    := header { field_decl } default_decl { rule_decl }
 *   header     := 'ruleset' IDENT ';'
 *   field_decl := 'field' IDENT ':' INT '..' INT ';'            (1..8 fields)
 *   default_decl := 'default' IDENT ';'
 *   rule_decl  := 'rule' IDENT ':' IDENT 'when' cond { 'and' cond } ';'
 *   cond       := IDENT 'in' INT '..' INT  |  IDENT '==' INT
 *
 * Statements are dispatched on their leading keyword; out-of-order
 * statements are diagnosed but still processed.  Error recovery is panic
 * mode with ';' as the synchronising token.  Semantic checks: duplicate or
 * unknown fields, empty domains / ranges, values outside the field domain,
 * duplicate rule ids, missing header / default, action and field limits.
 * Fields a rule does not mention match their whole domain; two conditions
 * on the same field are intersected.
 *
 * Complexity: O(T) in the number of tokens (plus O(F) field lookup per
 * condition, F <= 8).
 *
 * Compiler-design concept: a second front end sharing one IR (retargetable
 * compiler structure), LL(1) recursive descent, panic-mode recovery.
 */
#include "parser_ng.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { NT_IDENT, NT_INT, NT_KEYWORD, NT_COLON, NT_SEMI, NT_DOTDOT, NT_EQEQ, NT_EOF, NT_ERROR } NgTokType;

typedef struct {
    NgTokType type;
    int line, col;
    size_t offset;
    char lexeme[64];
    uint64_t ival;
} NgTok;

static const char *NG_KEYWORDS[] = {"ruleset", "field", "default", "rule", "when", "and", "in"};

static const char *ng_type_name(NgTokType t) {
    static const char *names[] = {"IDENT", "INT", "KEYWORD", "COLON", "SEMI", "DOTDOT", "EQEQ", "EOF", "ERROR"};
    return names[t];
}

typedef struct {
    NgTok *v;
    int n, cap;
} NgTokVec;

static void push_tok(NgTokVec *v, const NgTok *t) {
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 128;
        v->v = xrealloc(v->v, sizeof(NgTok) * (size_t)v->cap);
    }
    v->v[v->n++] = *t;
}

static void scan_ng(const char *src, NgTokVec *out, DiagList *d) {
    size_t i = 0;
    int line = 1, col = 1;
    for (;;) {
        NgTok t;
        memset(&t, 0, sizeof t);
        char c = src[i];
        /* skip blanks and comments */
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v') {
            if (c == '\n') { line++; col = 1; } else col++;
            i++;
            continue;
        }
        if (c == '#' || (c == '/' && src[i + 1] == '/')) {
            while (src[i] && src[i] != '\n') { i++; col++; }
            continue;
        }
        t.line = line;
        t.col = col;
        t.offset = i;
        size_t start = i;
        if (c == '\0') {
            t.type = NT_EOF;
            push_tok(out, &t);
            return;
        }
        if (isalpha((unsigned char)c) || c == '_') {
            while (isalnum((unsigned char)src[i]) || src[i] == '_') i++;
            t.type = NT_IDENT;
        } else if (isdigit((unsigned char)c)) {
            while (isdigit((unsigned char)src[i])) {
                if (t.ival < 99999999999ull) t.ival = t.ival * 10 + (uint64_t)(src[i] - '0');
                i++;
            }
            t.type = NT_INT;
            if (isalpha((unsigned char)src[i]) || src[i] == '_') {
                while (isalnum((unsigned char)src[i]) || src[i] == '_') i++;
                t.type = NT_ERROR;
            }
        } else {
            switch (c) {
            case ':': t.type = NT_COLON; i++; break;
            case ';': t.type = NT_SEMI; i++; break;
            case '.':
                if (src[i + 1] == '.') { t.type = NT_DOTDOT; i += 2; }
                else { t.type = NT_ERROR; i++; }
                break;
            case '=':
                if (src[i + 1] == '=') { t.type = NT_EQEQ; i += 2; }
                else { t.type = NT_ERROR; i++; }
                break;
            default: t.type = NT_ERROR; i++; break;
            }
        }
        size_t n = i - start;
        if (n >= sizeof t.lexeme) n = sizeof t.lexeme - 1;
        memcpy(t.lexeme, src + start, n);
        t.lexeme[n] = '\0';
        col += (int)(i - start);
        if (t.type == NT_IDENT)
            for (size_t k = 0; k < sizeof NG_KEYWORDS / sizeof NG_KEYWORDS[0]; k++)
                if (strcmp(t.lexeme, NG_KEYWORDS[k]) == 0) t.type = NT_KEYWORD;
        if (t.type == NT_ERROR)
            diag_add(d, DIAG_ERROR, t.line, t.col, "lexer",
                     "expected an identifier, a number, ':', ';', '..' or '=='",
                     "unexpected '%s'", t.lexeme);
        push_tok(out, &t);
    }
}

typedef struct {
    const char *src;
    NgTokVec toks;
    int pos;
    DiagList *d;
    Policy *pol;
    int seen_header, seen_default, seen_rule;
    int nrule_stmts;
} NgParser;

static const NgTok *peek(NgParser *p) { return &p->toks.v[p->pos]; }
static const NgTok *advance(NgParser *p) {
    const NgTok *t = &p->toks.v[p->pos];
    if (t->type != NT_EOF) p->pos++;
    return t;
}

static int is_kw(const NgTok *t, const char *kw) { return t->type == NT_KEYWORD && strcmp(t->lexeme, kw) == 0; }

static void synchronize(NgParser *p) {
    while (peek(p)->type != NT_SEMI && peek(p)->type != NT_EOF) advance(p);
    if (peek(p)->type == NT_SEMI) advance(p);
}

static int expect(NgParser *p, NgTokType type, const char *what, NgTok *out) {
    const NgTok *t = peek(p);
    if (t->type == type) {
        if (out) *out = *t;
        advance(p);
        return 1;
    }
    if (t->type != NT_ERROR)
        diag_add(p->d, DIAG_ERROR, t->line, t->col, "parser", "see the .ng grammar in the README",
                 "expected %s but found '%s'", what, t->type == NT_EOF ? "end of file" : t->lexeme);
    return 0;
}

static int expect_kw(NgParser *p, const char *kw) {
    const NgTok *t = peek(p);
    if (is_kw(t, kw)) { advance(p); return 1; }
    if (t->type != NT_ERROR)
        diag_add(p->d, DIAG_ERROR, t->line, t->col, "parser", "see the .ng grammar in the README",
                 "expected '%s' but found '%s'", kw, t->type == NT_EOF ? "end of file" : t->lexeme);
    return 0;
}

static int find_field(const Policy *pol, const char *name) {
    for (int k = 0; k < pol->nfields; k++)
        if (strcmp(pol->fields[k].name, name) == 0) return k;
    return -1;
}

static int int_value(NgParser *p, const NgTok *t, uint32_t *v) {
    if (t->ival > 0xFFFFFFFFull) {
        diag_add(p->d, DIAG_ERROR, t->line, t->col, "semantic", "values must fit in 32 bits",
                 "number %s is too large", t->lexeme);
        return 0;
    }
    *v = (uint32_t)t->ival;
    return 1;
}

/* header := 'ruleset' IDENT ';' */
static int parse_header(NgParser *p) {
    NgTok kw = *peek(p), name;
    advance(p);
    if (!expect(p, NT_IDENT, "a ruleset name", &name)) return 0;
    if (!expect(p, NT_SEMI, "';'", NULL)) return 0;
    if (p->seen_header)
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "semantic", "keep one ruleset header", "duplicate 'ruleset' header");
    else
        str_copy(p->pol->name, name.lexeme, sizeof p->pol->name);
    p->seen_header = 1;
    return 1;
}

/* field_decl := 'field' IDENT ':' INT '..' INT ';' */
static int parse_field(NgParser *p) {
    NgTok kw = *peek(p), name, lo, hi;
    advance(p);
    if (!expect(p, NT_IDENT, "a field name", &name)) return 0;
    if (!expect(p, NT_COLON, "':'", NULL)) return 0;
    if (!expect(p, NT_INT, "the lower bound of the domain", &lo)) return 0;
    if (!expect(p, NT_DOTDOT, "'..'", NULL)) return 0;
    if (!expect(p, NT_INT, "the upper bound of the domain", &hi)) return 0;
    if (!expect(p, NT_SEMI, "';'", NULL)) return 0;
    if (p->seen_default || p->seen_rule)
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "parser", "declare all fields first",
                 "field declarations must come before 'default' and the rules");
    uint32_t a = 0, b = 0;
    if (!int_value(p, &lo, &a) || !int_value(p, &hi, &b)) return 1;
    if (a > b) {
        diag_add(p->d, DIAG_ERROR, lo.line, lo.col, "semantic", "write the lower bound first",
                 "domain %u .. %u of field '%s' is empty", (unsigned)a, (unsigned)b, name.lexeme);
        return 1;
    }
    if (find_field(p->pol, name.lexeme) >= 0) {
        diag_add(p->d, DIAG_ERROR, name.line, name.col, "semantic", "field names must be unique",
                 "duplicate field '%s'", name.lexeme);
        return 1;
    }
    if (p->pol->nfields >= NG_MAX_FIELDS) {
        diag_add(p->d, DIAG_ERROR, name.line, name.col, "limits", "at most 8 fields are supported",
                 "too many fields (the limit is %d)", NG_MAX_FIELDS);
        return 1;
    }
    FieldDecl *f = &p->pol->fields[p->pol->nfields++];
    str_copy(f->name, name.lexeme, sizeof f->name);
    f->domain = (Range){a, b};
    return 1;
}

/* default_decl := 'default' IDENT ';' */
static int parse_default(NgParser *p) {
    NgTok kw = *peek(p), act;
    advance(p);
    if (!expect(p, NT_IDENT, "an action name", &act)) return 0;
    if (!expect(p, NT_SEMI, "';'", NULL)) return 0;
    if (p->seen_default) {
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "semantic", "keep a single default", "duplicate 'default'");
        return 1;
    }
    if (p->seen_rule)
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "parser", "move 'default' above the rules",
                 "'default' must come before the rules");
    p->seen_default = 1;
    int a = policy_intern_action(p->pol, act.lexeme);
    if (a < 0)
        diag_add(p->d, DIAG_ERROR, act.line, act.col, "limits", "use fewer distinct actions",
                 "too many actions (the limit is %d)", NG_MAX_ACTIONS);
    else
        p->pol->default_action = a;
    return 1;
}

/* cond := IDENT 'in' INT '..' INT | IDENT '==' INT ; intersects into r */
static int parse_cond(NgParser *p, Rule *r, int *valid) {
    NgTok name, lo, hi;
    if (!expect(p, NT_IDENT, "a field name", &name)) return 0;
    if (is_kw(peek(p), "in")) {
        advance(p);
        if (!expect(p, NT_INT, "a number", &lo)) return 0;
        if (!expect(p, NT_DOTDOT, "'..'", NULL)) return 0;
        if (!expect(p, NT_INT, "a number", &hi)) return 0;
    } else if (peek(p)->type == NT_EQEQ) {
        advance(p);
        if (!expect(p, NT_INT, "a number", &lo)) return 0;
        hi = lo;
    } else {
        expect(p, NT_EQEQ, "'in' or '=='", NULL);
        return 0;
    }
    int k = find_field(p->pol, name.lexeme);
    if (k < 0) {
        diag_add(p->d, DIAG_ERROR, name.line, name.col, "semantic", "declare it with 'field NAME : lo .. hi;'",
                 "unknown field '%s'", name.lexeme);
        *valid = 0;
        return 1;
    }
    uint32_t a = 0, b = 0;
    if (!int_value(p, &lo, &a) || !int_value(p, &hi, &b)) { *valid = 0; return 1; }
    Range dom = p->pol->fields[k].domain;
    if (a > b) {
        diag_add(p->d, DIAG_ERROR, lo.line, lo.col, "semantic", "write the lower bound first",
                 "range %u .. %u is empty", (unsigned)a, (unsigned)b);
        *valid = 0;
        return 1;
    }
    if (a < dom.lo || b > dom.hi) {
        diag_add(p->d, DIAG_ERROR, lo.line, lo.col, "semantic", "stay inside the declared domain",
                 "range %u .. %u is outside the domain %u .. %u of field '%s'", (unsigned)a, (unsigned)b,
                 (unsigned)dom.lo, (unsigned)dom.hi, name.lexeme);
        *valid = 0;
        return 1;
    }
    Range cur = r->cond[k];
    Range nr = {a > cur.lo ? a : cur.lo, b < cur.hi ? b : cur.hi};
    if (nr.lo > nr.hi) {
        diag_add(p->d, DIAG_ERROR, name.line, name.col, "semantic", "this rule can never match",
                 "conditions on field '%s' do not overlap", name.lexeme);
        *valid = 0;
        return 1;
    }
    r->cond[k] = nr;
    return 1;
}

/* rule_decl := 'rule' IDENT ':' IDENT 'when' cond { 'and' cond } ';' */
static int parse_rule(NgParser *p) {
    NgTok kw = *peek(p), id, act;
    advance(p);
    p->nrule_stmts++;
    if (!expect(p, NT_IDENT, "a rule id", &id)) return 0;
    if (!expect(p, NT_COLON, "':'", NULL)) return 0;
    if (!expect(p, NT_IDENT, "an action name", &act)) return 0;
    if (!expect_kw(p, "when")) return 0;
    Rule r;
    memset(&r, 0, sizeof r);
    for (int k = 0; k < p->pol->nfields; k++) r.cond[k] = p->pol->fields[k].domain;
    int valid = 1;
    if (!parse_cond(p, &r, &valid)) return 0;
    while (is_kw(peek(p), "and")) {
        advance(p);
        if (!parse_cond(p, &r, &valid)) return 0;
    }
    NgTok semi;
    if (!expect(p, NT_SEMI, "';' or 'and'", &semi)) return 0;

    if (!p->seen_default && !p->seen_rule)
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "parser", "add 'default ACTION;' before the rules",
                 "rules must come after the 'default' declaration");
    p->seen_rule = 1;
    for (int i = 0; i < p->pol->nrules; i++)
        if (strcmp(p->pol->rules[i].id, id.lexeme) == 0) {
            diag_add(p->d, DIAG_ERROR, id.line, id.col, "semantic", "rule ids must be unique",
                     "duplicate rule id '%s'", id.lexeme);
            valid = 0;
        }
    if (!valid) return 1;
    int a = policy_intern_action(p->pol, act.lexeme);
    if (a < 0) {
        diag_add(p->d, DIAG_ERROR, act.line, act.col, "limits", "use fewer distinct actions",
                 "too many actions (the limit is %d)", NG_MAX_ACTIONS);
        return 1;
    }
    if (p->pol->nrules >= NG_MAX_RULES) {
        diag_add(p->d, DIAG_ERROR, kw.line, kw.col, "limits", "split the rule set",
                 "too many rules (the limit is %d)", NG_MAX_RULES);
        return 1;
    }
    r.action = a;
    r.line = kw.line;
    str_copy(r.id, id.lexeme, sizeof r.id);
    size_t n = semi.offset + 1 - kw.offset;
    if (n >= sizeof r.text) n = sizeof r.text - 1;
    memcpy(r.text, p->src + kw.offset, n);
    r.text[n] = '\0';
    for (char *c = r.text; *c; c++)
        if (*c == '\n' || *c == '\r' || *c == '\t') *c = ' ';
    policy_add_rule(p->pol, &r);
    return 1;
}

int parse_ng(const char *src, Policy *out, DiagList *diags, TokLog *log, double *lex_ms) {
    NgParser p;
    memset(&p, 0, sizeof p);
    p.src = src;
    p.d = diags;
    p.pol = out;
    policy_init(out);
    str_copy(out->name, "ruleset", sizeof out->name);
    long t0 = clock_now();
    scan_ng(src, &p.toks, diags);
    if (lex_ms) *lex_ms = ms_since(t0);
    if (log)
        for (int i = 0; i < p.toks.n; i++)
            tok_log_add(log, ng_type_name(p.toks.v[i].type), p.toks.v[i].line, p.toks.v[i].col,
                        p.toks.v[i].lexeme);

    while (peek(&p)->type != NT_EOF) {
        const NgTok *t = peek(&p);
        int ok;
        if (is_kw(t, "ruleset")) ok = parse_header(&p);
        else if (is_kw(t, "field")) ok = parse_field(&p);
        else if (is_kw(t, "default")) ok = parse_default(&p);
        else if (is_kw(t, "rule")) ok = parse_rule(&p);
        else {
            if (t->type != NT_ERROR)
                diag_add(diags, DIAG_ERROR, t->line, t->col, "parser",
                         "statements start with ruleset, field, default or rule",
                         "unexpected '%s' at the start of a statement", t->lexeme);
            ok = 0;
        }
        if (!ok) synchronize(&p);
    }
    const NgTok *eof = peek(&p);
    if (!p.seen_header)
        diag_add(diags, DIAG_ERROR, 1, 1, "parser", "start the file with 'ruleset NAME;'", "missing 'ruleset' header");
    if (out->nfields == 0)
        diag_add(diags, DIAG_ERROR, eof->line, eof->col, "semantic", "declare 1 to 8 fields",
                 "no fields declared");
    if (!p.seen_default)
        diag_add(diags, DIAG_ERROR, eof->line, eof->col, "parser", "add 'default ACTION;'",
                 "missing 'default' declaration");
    free(p.toks.v);
    diag_sort(diags);
    return diag_errors(diags);
}
