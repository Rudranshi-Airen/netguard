/*
 * parser_fw.c -- Recursive-descent parser for the .fw firewall language.
 *
 * Grammar (one function per non-terminal below; NEWLINE ends a statement):
 *
 *   policy       := { stmt NEWLINE }
 *   stmt         := rule | default_decl | epsilon
 *   default_decl := 'DEFAULT' action
 *   rule         := action proto 'FROM' addr 'TO' addr [ 'PORT' portspec ]
 *   action       := 'ALLOW' | 'DENY'
 *   proto        := 'TCP' | 'UDP' | 'ICMP' | 'ANY' | INT
 *   addr         := 'ANY' | IPV4 | CIDR | IPV4 '-' IPV4
 *   portspec     := 'ANY' | INT | INT '-' INT
 *
 * The grammar is LL(1): every decision is made by looking at one token
 * (e.g. after an IPV4, a DASH selects the range alternative of addr).
 *
 * Error recovery is panic mode: on a syntax error the parser reports one
 * diagnostic, discards tokens up to the synchronising token NEWLINE and
 * resumes with the next statement, so every erroneous line is reported.
 * An ERROR token from the lexer has already been reported, so it triggers
 * silent recovery (no cascade of follow-on errors).
 *
 * Each syntactically valid rule is handed to sema.c, which performs the
 * semantic checks and lowers it to an IR Rule.
 *
 * Complexity: O(T) in the number of tokens (each token is consumed or
 * skipped exactly once).
 *
 * Compiler-design concept: top-down predictive (LL(1)) parsing by
 * recursive descent, with panic-mode error recovery.
 */
#include "parser_fw.h"
#include "sema.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *src;
    TokenVec toks;
    int pos;
    DiagList *diags;
    RawRule *rules;
    int nrules, caprules;
    RawDefault *defs;
    int ndefs, capdefs;
} Parser;

static const Token *peek(Parser *p) { return &p->toks.v[p->pos]; }

static const Token *advance(Parser *p) {
    const Token *t = &p->toks.v[p->pos];
    if (t->type != TOK_EOF) p->pos++;
    return t;
}

/* Panic mode: skip to and past the next NEWLINE (or stop at EOF). */
static void synchronize(Parser *p) {
    while (peek(p)->type != TOK_NEWLINE && peek(p)->type != TOK_EOF) advance(p);
    if (peek(p)->type == TOK_NEWLINE) advance(p);
}

static const char *describe(const Token *t) {
    switch (t->type) {
    case TOK_NEWLINE: return "end of line";
    case TOK_EOF: return "end of file";
    default: return t->lexeme;
    }
}

/* Report "expected X" unless the offending token is a lexer ERROR token. */
static void syntax_error(Parser *p, const char *expected, const char *hint) {
    const Token *t = peek(p);
    if (t->type == TOK_ERROR) return;
    diag_add(p->diags, DIAG_ERROR, t->line, t->col, "parser", hint,
             "expected %s but found '%s'", expected, describe(t));
}

static int accept(Parser *p, TokType type, Token *out) {
    if (peek(p)->type != type) return 0;
    if (out) *out = *peek(p);
    advance(p);
    return 1;
}

/* action := 'ALLOW' | 'DENY' */
static int parse_action(Parser *p, Token *out) {
    if (accept(p, TOK_ACTION, out)) return 1;
    syntax_error(p, "ALLOW or DENY", "an action is ALLOW or DENY");
    return 0;
}

/* proto := 'TCP' | 'UDP' | 'ICMP' | 'ANY' | INT */
static int parse_proto(Parser *p, Token *out) {
    if (accept(p, TOK_PROTO, out) || accept(p, TOK_ANY, out) || accept(p, TOK_INT, out)) return 1;
    syntax_error(p, "a protocol (TCP, UDP, ICMP, ANY or a number)",
                 "the protocol comes right after the action, e.g. ALLOW TCP ...");
    return 0;
}

/* addr := 'ANY' | IPV4 | CIDR | IPV4 '-' IPV4 */
static int parse_addr(Parser *p, RawAddr *a) {
    memset(a, 0, sizeof *a);
    if (accept(p, TOK_ANY, &a->a)) { a->kind = ADDR_ANY; return 1; }
    if (accept(p, TOK_CIDR, &a->a)) { a->kind = ADDR_CIDR; return 1; }
    if (accept(p, TOK_IPV4, &a->a)) {
        a->kind = ADDR_IP;
        if (accept(p, TOK_DASH, NULL)) {
            if (!accept(p, TOK_IPV4, &a->b)) {
                syntax_error(p, "an IPv4 address after '-'", "an address range is written a.b.c.d-e.f.g.h");
                return 0;
            }
            a->kind = ADDR_RANGE;
        }
        return 1;
    }
    syntax_error(p, "an address (ANY, IPv4, CIDR or IPv4-IPv4)", "e.g. ANY, 10.0.0.1, 10.0.0.0/8");
    return 0;
}

/* portspec := 'ANY' | INT | INT '-' INT */
static int parse_portspec(Parser *p, RawRule *r) {
    if (accept(p, TOK_ANY, NULL)) { r->port_kind = PORT_ANY; return 1; }
    if (accept(p, TOK_INT, &r->p1)) {
        r->port_kind = PORT_SINGLE;
        if (accept(p, TOK_DASH, NULL)) {
            if (!accept(p, TOK_INT, &r->p2)) {
                syntax_error(p, "a port number after '-'", "a port range is written lo-hi, e.g. 80-89");
                return 0;
            }
            r->port_kind = PORT_RANGE;
        }
        return 1;
    }
    syntax_error(p, "a port (ANY, N or N-M)", "e.g. PORT 22 or PORT 8000-8100");
    return 0;
}

/* rule := action proto 'FROM' addr 'TO' addr [ 'PORT' portspec ] */
static int parse_rule(Parser *p, RawRule *r) {
    memset(r, 0, sizeof *r);
    r->line = peek(p)->line;
    if (!parse_action(p, &r->action)) return 0;
    if (!parse_proto(p, &r->proto)) return 0;
    if (!accept(p, TOK_FROM, NULL)) {
        syntax_error(p, "FROM", "rules have the form ACTION PROTO FROM addr TO addr [PORT p]");
        return 0;
    }
    if (!parse_addr(p, &r->src)) return 0;
    if (!accept(p, TOK_TO, NULL)) {
        syntax_error(p, "TO", "rules have the form ACTION PROTO FROM addr TO addr [PORT p]");
        return 0;
    }
    if (!parse_addr(p, &r->dst)) return 0;
    r->port_kind = PORT_OMITTED;
    if (accept(p, TOK_PORT, &r->port_kw)) {
        if (!parse_portspec(p, r)) return 0;
    }
    return 1;
}

/* default_decl := 'DEFAULT' action */
static int parse_default(Parser *p, RawDefault *d) {
    accept(p, TOK_DEFAULT, &d->kw);
    return parse_action(p, &d->action);
}

/* A statement must be followed by NEWLINE or EOF. */
static int expect_end(Parser *p) {
    if (peek(p)->type == TOK_NEWLINE || peek(p)->type == TOK_EOF) return 1;
    syntax_error(p, "end of line", "put one statement per line");
    return 0;
}

/* stmt := rule | default_decl | epsilon */
static void parse_stmt(Parser *p) {
    const Token *t = peek(p);
    if (t->type == TOK_NEWLINE) { advance(p); return; }
    if (t->type == TOK_ACTION) {
        RawRule r;
        if (parse_rule(p, &r) && expect_end(p)) {
            if (p->nrules == p->caprules) {
                p->caprules = p->caprules ? p->caprules * 2 : 16;
                p->rules = xrealloc(p->rules, sizeof(RawRule) * (size_t)p->caprules);
            }
            p->rules[p->nrules++] = r;
        }
    } else if (t->type == TOK_DEFAULT) {
        RawDefault d;
        if (parse_default(p, &d) && expect_end(p)) {
            if (p->ndefs == p->capdefs) {
                p->capdefs = p->capdefs ? p->capdefs * 2 : 4;
                p->defs = xrealloc(p->defs, sizeof(RawDefault) * (size_t)p->capdefs);
            }
            p->defs[p->ndefs++] = d;
        }
    } else {
        syntax_error(p, "ALLOW, DENY or DEFAULT at the start of a statement",
                     "every line is a rule, a DEFAULT declaration, a comment or blank");
    }
    synchronize(p);
}

/* policy := { stmt NEWLINE } */
static void parse_policy(Parser *p) {
    while (peek(p)->type != TOK_EOF) parse_stmt(p);
}

/* Source text of a line, without its comment, trimmed. */
static void line_text(const char *src, int line, char *buf, size_t cap) {
    const char *s = src;
    for (int l = 1; l < line && *s; s++)
        if (*s == '\n') l++;
    const char *e = s;
    while (*e && *e != '\n' && *e != '#') e++;
    while (s < e && (*s == ' ' || *s == '\t')) s++;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r')) e--;
    size_t n = (size_t)(e - s);
    if (n >= cap) n = cap - 1;
    memcpy(buf, s, n);
    buf[n] = '\0';
}

int parse_fw(const char *src, Policy *out, DiagList *diags, TokLog *log, double *lex_ms) {
    Parser p;
    memset(&p, 0, sizeof p);
    p.src = src;
    p.diags = diags;
    long t0 = clock_now();
    lex_fw(src, &p.toks, diags);
    if (lex_ms) *lex_ms = ms_since(t0);
    if (log)
        for (int i = 0; i < p.toks.n; i++)
            tok_log_add(log, tok_type_name(p.toks.v[i].type), p.toks.v[i].line, p.toks.v[i].col,
                        p.toks.v[i].lexeme);

    parse_policy(&p);

    sema_fw_init_policy(out);
    for (int i = 0; i < p.nrules; i++) {
        Rule r;
        if (sema_fw_rule(out, &p.rules[i], &r, diags) != 0) continue;
        if (out->nrules >= NG_MAX_RULES) {
            diag_add(diags, DIAG_ERROR, r.line, 1, "limits", "split the policy into smaller files",
                     "too many rules (the limit is %d)", NG_MAX_RULES);
            break;
        }
        snprintf(r.id, sizeof r.id, "R%d", i + 1);
        line_text(src, r.line, r.text, sizeof r.text);
        policy_add_rule(out, &r);
    }
    sema_fw_defaults(out, p.defs, p.ndefs, diags);

    free(p.rules);
    free(p.defs);
    tokvec_free(&p.toks);
    diag_sort(diags);
    return diag_errors(diags);
}
