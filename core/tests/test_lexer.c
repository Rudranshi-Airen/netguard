/*
 * test_lexer.c -- The hand-written DFA scanner.
 */
#include "lexer.h"
#include "test.h"

static int lex_types(const char *src, TokType *out, int cap, DiagList *d) {
    TokenVec v = {NULL, 0, 0};
    lex_fw(src, &v, d);
    int n = v.n < cap ? v.n : cap;
    for (int i = 0; i < n; i++) out[i] = v.v[i].type;
    tokvec_free(&v);
    return n;
}

void test_lexer(void) {
    DiagList d;
    TokType t[32];

    /* IPv4 and CIDR are recognised by the scanner, with their values. */
    diag_init(&d);
    TokenVec v = {NULL, 0, 0};
    lex_fw("ALLOW TCP FROM 10.0.0.0/8 TO 192.168.1.20", &v, &d);
    CHECK_EQ(v.n, 7);
    CHECK_EQ(v.v[3].type, TOK_CIDR);
    CHECK_EQ(v.v[3].oct[0], 10);
    CHECK_EQ(v.v[3].prefix, 8);
    CHECK_EQ(v.v[5].type, TOK_IPV4);
    CHECK_EQ(v.v[5].oct[2], 1);
    CHECK_EQ(v.v[5].oct[3], 20);
    CHECK_EQ(v.v[5].col, 30);
    CHECK_STR(v.v[5].lexeme, "192.168.1.20");
    CHECK_EQ(v.v[6].type, TOK_EOF);
    CHECK_EQ(d.count, 0);
    tokvec_free(&v);
    diag_free(&d);

    /* Ranges: INT DASH INT and IPV4 DASH IPV4 */
    diag_init(&d);
    int n = lex_types("PORT 80-89 1.2.3.4-1.2.3.9", t, 32, &d);
    TokType want_r[] = {TOK_PORT, TOK_INT, TOK_DASH, TOK_INT, TOK_IPV4, TOK_DASH, TOK_IPV4, TOK_EOF};
    CHECK_EQ(n, 8);
    for (int i = 0; i < 8 && i < n; i++) CHECK_EQ(t[i], want_r[i]);
    diag_free(&d);

    /* Comments (full line and end of line) and NEWLINE tokens. */
    diag_init(&d);
    n = lex_types("# header\nDENY ANY FROM ANY TO ANY   # tail comment\n\n", t, 32, &d);
    TokType want_c[] = {TOK_NEWLINE, TOK_ACTION, TOK_ANY, TOK_FROM, TOK_ANY, TOK_TO, TOK_ANY,
                        TOK_NEWLINE, TOK_NEWLINE, TOK_EOF};
    CHECK_EQ(n, 10);
    for (int i = 0; i < 10 && i < n; i++) CHECK_EQ(t[i], want_c[i]);
    CHECK_EQ(d.count, 0);
    diag_free(&d);

    /* Keywords are case-insensitive. */
    diag_init(&d);
    n = lex_types("allow Tcp fRoM any To ANY port 22 default deny icmp udp", t, 32, &d);
    TokType want_k[] = {TOK_ACTION, TOK_PROTO, TOK_FROM, TOK_ANY, TOK_TO, TOK_ANY, TOK_PORT, TOK_INT,
                        TOK_DEFAULT, TOK_ACTION, TOK_PROTO, TOK_PROTO, TOK_EOF};
    CHECK_EQ(n, 13);
    for (int i = 0; i < 13 && i < n; i++) CHECK_EQ(t[i], want_k[i]);
    CHECK_EQ(d.count, 0);
    diag_free(&d);

    /* Error tokens: each produces one diagnostic and scanning continues. */
    diag_init(&d);
    n = lex_types("PERMIT @ 10.0.0 22abc 1.2.3.4/ ALLOW", t, 32, &d);
    TokType want_e[] = {TOK_ERROR, TOK_ERROR, TOK_ERROR, TOK_ERROR, TOK_ERROR, TOK_ACTION, TOK_EOF};
    CHECK_EQ(n, 7);
    for (int i = 0; i < 7 && i < n; i++) CHECK_EQ(t[i], want_e[i]);
    CHECK_EQ(d.count, 5);
    CHECK(strstr(d.items[0].hint, "ALLOW") != NULL);   /* PERMIT -> suggest ALLOW */
    diag_free(&d);

    /* Octets > 255 still lex as IPV4: the range check is semantic. */
    diag_init(&d);
    v = (TokenVec){NULL, 0, 0};
    lex_fw("300.1.2.3 10.0.0.0/33", &v, &d);
    CHECK_EQ(v.v[0].type, TOK_IPV4);
    CHECK_EQ(v.v[0].oct[0], 300);
    CHECK_EQ(v.v[1].type, TOK_CIDR);
    CHECK_EQ(v.v[1].prefix, 33);
    CHECK_EQ(d.count, 0);
    tokvec_free(&v);
    diag_free(&d);

    /* Line / column tracking across lines. */
    diag_init(&d);
    v = (TokenVec){NULL, 0, 0};
    lex_fw("DENY ANY\n  FROM", &v, &d);
    CHECK_EQ(v.v[3].type, TOK_FROM);
    CHECK_EQ(v.v[3].line, 2);
    CHECK_EQ(v.v[3].col, 3);
    tokvec_free(&v);
    diag_free(&d);
}
