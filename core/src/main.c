/*
 * main.c -- Command-line interface of the netguard compiler.
 *
 *   netguard compile  FILE [--syntax fw|ng] [--json] [--min-by action|rule]
 *   netguard classify FILE --packet "proto=TCP src_ip=... dst_ip=... dst_port=22" [--json]
 *   netguard classify-batch FILE < packets.txt      (one JSON result per line)
 *   netguard verify   FILE [--n 10000] [--seed 42]  (JSON)
 *   netguard dot      FILE --stage nfa|dfa|min [--min-by action|rule]
 *
 * Exit codes: 0 success, 1 compile errors (diagnostics are still printed /
 * included in the JSON), 2 usage error (bad arguments, unreadable file,
 * malformed packet).
 *
 * This file only parses arguments and prints; all compilation happens in
 * pipeline.c and the phase modules.
 */
#include "compare.h"
#include "dot.h"
#include "pipeline.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *cmd, *file, *file2, *packet, *stage;
    int json, syntax_given;
    Syntax syntax;
    MinMode min_mode;
    long n;
    uint64_t seed;
} Args;

static void usage(void) {
    fputs("usage:\n"
          "  netguard compile  FILE [--syntax fw|ng] [--json] [--min-by action|rule]\n"
          "  netguard classify FILE --packet \"proto=TCP src_ip=10.1.2.3 dst_ip=8.8.8.8 dst_port=22\" [--json]\n"
          "  netguard classify-batch FILE [--syntax fw|ng] < packets.txt\n"
          "  netguard verify   FILE [--n 10000] [--seed 42]\n"
          "  netguard dot      FILE --stage nfa|dfa|min [--min-by action|rule]\n"
          "  netguard equiv    ORIGINAL SUGGESTED [--syntax fw|ng] [--json]\n",
          stderr);
}

static int parse_args(int argc, char **argv, Args *a) {
    memset(a, 0, sizeof *a);
    a->n = 10000;
    a->seed = 42;
    if (argc < 3) return -1;
    a->cmd = argv[1];
    a->file = argv[2];
    int first_opt = 3;
    if (strcmp(a->cmd, "equiv") == 0) {          /* two input files */
        if (argc < 4 || argv[3][0] == '-') { fputs("netguard: equiv needs ORIGINAL and SUGGESTED files\n", stderr); return -1; }
        a->file2 = argv[3];
        first_opt = 4;
    }
    for (int i = first_opt; i < argc; i++) {
        const char *o = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (strcmp(o, "--json") == 0) { a->json = 1; continue; }
        if (!v) { fprintf(stderr, "netguard: option %s needs a value\n", o); return -1; }
        i++;
        if (strcmp(o, "--syntax") == 0) {
            if (strcmp(v, "fw") == 0) a->syntax = SYNTAX_FW;
            else if (strcmp(v, "ng") == 0) a->syntax = SYNTAX_NG;
            else { fprintf(stderr, "netguard: --syntax must be fw or ng\n"); return -1; }
            a->syntax_given = 1;
        } else if (strcmp(o, "--packet") == 0) a->packet = v;
        else if (strcmp(o, "--stage") == 0) a->stage = v;
        else if (strcmp(o, "--min-by") == 0) {
            if (strcmp(v, "action") == 0) a->min_mode = MIN_BY_ACTION;
            else if (strcmp(v, "rule") == 0) a->min_mode = MIN_BY_RULE;
            else { fprintf(stderr, "netguard: --min-by must be action or rule\n"); return -1; }
        } else if (strcmp(o, "--n") == 0) {
            a->n = strtol(v, NULL, 10);
            if (a->n <= 0 || a->n > 10000000) { fprintf(stderr, "netguard: --n must be 1..10000000\n"); return -1; }
        } else if (strcmp(o, "--seed") == 0) a->seed = strtoull(v, NULL, 10);
        else { fprintf(stderr, "netguard: unknown option %s\n", o); return -1; }
    }
    if (!a->syntax_given) {
        size_t n = strlen(a->file);
        a->syntax = (n >= 3 && str_ieq(a->file + n - 3, ".ng")) ? SYNTAX_NG : SYNTAX_FW;
    }
    return 0;
}

static void print_json_and_free(Json *j) {
    char *s = json_take(j);
    fputs(s, stdout);
    fputc('\n', stdout);
    free(s);
}

static void print_diags(const char *file, const DiagList *d) {
    for (int i = 0; i < d->count; i++) {
        const Diag *g = &d->items[i];
        fprintf(stderr, "%s:%d:%d: %s: %s", file, g->line, g->col, g->level == DIAG_ERROR ? "error" : "warning",
                g->message);
        if (g->hint[0]) fprintf(stderr, "  [hint: %s]", g->hint);
        fputc('\n', stderr);
    }
}

static void print_compile_text(const Pipeline *pl) {
    const Policy *p = &pl->pol;
    printf("NetGuard  policy '%s'  (%d rules, %d fields, default %s)\n", p->name, p->nrules, p->nfields,
           p->actions[p->default_action]);
    printf("Partition: ");
    for (int k = 0; k < pl->pt.nfields; k++) printf("%s%s=%d", k ? " " : "", p->fields[k].name, pl->pt.f[k].nsyms);
    printf("  -> %llu cells, alphabet %d symbols\n", (unsigned long long)pl->pt.cells, pl->pt.total_syms);
    printf("Automata:  NFA %d (eps %d, sym %d) -> DFA %d (final %d) -> Min %d (by rule: %d)\n", pl->c.nfa.nstates,
           pl->c.nfa.eps_edges, pl->c.nfa.sym_edges, pl->c.dfa.nstates, dfa_final_count(&pl->c.dfa), pl->c.min.nstates,
           pl->min_rule.nstates);
    printf("Analysis:  ok=%d shadowed=%d partial=%d redundant=%d\n", pl->an.count[ST_OK], pl->an.count[ST_SHADOWED],
           pl->an.count[ST_PARTIAL], pl->an.count[ST_REDUNDANT]);
    for (int i = 0; i < p->nrules; i++) {
        const RuleReport *r = &pl->an.r[i];
        printf("  %-5s %-9s %-36s %s\n", p->rules[i].id, status_name(r->status), r->subtype, r->severity);
    }
    printf("Optimization: %d -> %d rules\n", pl->opt.original_rules, pl->opt.optimized_rules);
    for (int i = 0; i < pl->opt.nremoved; i++)
        printf("  %d. remove %-5s %s\n", i + 1, p->rules[pl->opt.removed[i].index].id, pl->opt.removed[i].reason);
    printf("Equivalence (optimized vs original): %s\n", pl->eq.equivalent ? "EQUIVALENT" : "NOT EQUIVALENT");
    printf("Optimized policy:\n%s", pl->opt.source);
}

static void print_classify_text(const Pipeline *pl, const uint32_t *vals) {
    const Policy *p = &pl->pol;
    Classification c;
    classify_packet(&c, p, &pl->pt, &pl->c.min, &pl->c.dfa, vals);
    char buf[256], v[40], r[96];
    fmt_packet(p, vals, buf, sizeof buf);
    printf("Packet:   %s\n", buf);
    printf("Decision: %s  (by %s)\n", p->actions[c.decision], c.winner >= 0 ? p->rules[c.winner].id : "DEFAULT");
    printf("Matched:  ");
    int any = 0;
    for (int i = rs_lowest(&c.matched); i >= 0; i = rs_next(&c.matched, i)) { printf("%s%s", any ? ", " : "", p->rules[i].id); any = 1; }
    printf("%s\n", any ? "" : "(none)");
    for (int f = 0; f < c.nfails; f++) {
        const Rule *ru = &p->rules[c.fails[f].rule];
        int k = c.fails[f].field;
        fmt_value(p, k, vals[k], v, sizeof v);
        fmt_range(p, k, ru->cond[k], r, sizeof r);
        printf("  %s: %s %s \xE2\x88\x89 %s\n", ru->id, p->fields[k].name, v, r);
    }
    printf("Trace (min-DFA states):\n");
    for (int k = 0; k < p->nfields; k++) {
        const TraceStep *t = &c.trace[k];
        Range ir = {t->iv.lo, t->iv.hi};
        fmt_value(p, k, t->value, v, sizeof v);
        fmt_range(p, k, ir, r, sizeof r);
        printf("  %-9s %-16s sym %-3d %-28s M%d -> M%d\n", p->fields[k].name, v, t->sym, r, t->from, t->to);
    }
    printf("Oracle:   %s (%s)\n", p->actions[c.oracle_decision],
           c.oracle_winner >= 0 ? p->rules[c.oracle_winner].id : "DEFAULT");
}

/* netguard equiv ORIGINAL SUGGESTED: exit 0 = equivalent, 3 = not equivalent,
 * 1 = a file has errors / the policies are not comparable, 2 = usage. */
static int run_equiv(const Args *a) {
    char *sa = read_file(a->file), *sb = read_file(a->file2);
    if (!sa || !sb) {
        fprintf(stderr, "netguard: cannot read '%s'\n", !sa ? a->file : a->file2);
        free(sa);
        free(sb);
        return 2;
    }
    Compare c;
    int rc = compare_sources(&c, sa, sb, a->syntax);
    free(sa);
    free(sb);
    if (a->json) {
        Json j;
        json_init(&j);
        emit_compare_json(&j, &c);
        print_json_and_free(&j);
        json_free(&j);
    } else {
        print_diags(a->file, &c.diag_a);
        print_diags(a->file2, &c.diag_b);
        if (!c.compared) {
            printf("Cannot compare: %s\n", c.error);
        } else if (c.er.equivalent) {
            printf("EQUIVALENT: %d rules vs %d rules decide every packet identically (%d product pairs explored)\n",
                   c.a.nrules, c.b.nrules, c.er.pairs_explored);
        } else {
            char text[256];
            fmt_packet(&c.a, c.er.packet, text, sizeof text);
            printf("NOT EQUIVALENT\n  counterexample: %s\n  original:  %s (by %s)\n  suggested: %s (by %s)\n", text,
                   c.a.actions[c.er.action_a], c.winner_a >= 0 ? c.a.rules[c.winner_a].id : "DEFAULT",
                   c.a.actions[c.er.action_b], c.winner_b >= 0 ? c.b.rules[c.winner_b].id : "DEFAULT");
        }
    }
    (void)rc;
    int code = !c.compared ? 1 : (c.er.equivalent ? 0 : 3);
    compare_free(&c);
    return code;
}

int main(int argc, char **argv) {
    Args a;
    if (parse_args(argc, argv, &a) != 0) { usage(); return 2; }
    if (strcmp(a.cmd, "equiv") == 0) return run_equiv(&a);
    int is_compile = strcmp(a.cmd, "compile") == 0, is_classify = strcmp(a.cmd, "classify") == 0,
        is_batch = strcmp(a.cmd, "classify-batch") == 0, is_verify = strcmp(a.cmd, "verify") == 0,
        is_dot = strcmp(a.cmd, "dot") == 0;
    if (!(is_compile || is_classify || is_batch || is_verify || is_dot)) {
        fprintf(stderr, "netguard: unknown command '%s'\n", a.cmd);
        usage();
        return 2;
    }
    if (is_classify && !a.packet) { fputs("netguard: classify needs --packet\n", stderr); return 2; }
    if (is_dot && (!a.stage || (strcmp(a.stage, "nfa") && strcmp(a.stage, "dfa") && strcmp(a.stage, "min")))) {
        fputs("netguard: dot needs --stage nfa|dfa|min\n", stderr);
        return 2;
    }
    char *src = read_file(a.file);
    if (!src) { fprintf(stderr, "netguard: cannot read '%s'\n", a.file); return 2; }

    Pipeline pl;
    RunLevel level = (is_compile || is_verify) ? RUN_FULL : RUN_AUTOMATA;
    pipeline_run(&pl, src, a.syntax, a.min_mode, level);
    free(src);
    int rc = 0;
    Json j;
    json_init(&j);

    if (is_compile) {
        if (a.json) {
            emit_compile_json(&j, &pl);
            print_json_and_free(&j);
        } else {
            print_diags(a.file, &pl.diags);
            if (pl.ok) print_compile_text(&pl);
        }
        rc = pl.ok ? 0 : 1;
    } else if (!pl.ok) {
        if (a.json || is_batch || is_verify) {
            emit_compile_json(&j, &pl);
            print_json_and_free(&j);
        } else {
            print_diags(a.file, &pl.diags);
        }
        rc = 1;
    } else if (is_classify) {
        uint32_t vals[NG_MAX_FIELDS];
        char err[200];
        if (parse_packet(&pl.pol, a.packet, vals, err, sizeof err) != 0) {
            if (a.json) { emit_error_json(&j, err); print_json_and_free(&j); }
            else fprintf(stderr, "netguard: %s\n", err);
            rc = 2;
        } else if (a.json) {
            emit_classify_json(&j, &pl, vals, a.packet);
            print_json_and_free(&j);
        } else {
            print_classify_text(&pl, vals);
        }
    } else if (is_batch) {
        char line[4096];
        while (fgets(line, sizeof line, stdin)) {
            size_t n = strlen(line);
            while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
            const char *s = line;
            while (*s == ' ' || *s == '\t') s++;
            if (!*s || *s == '#') continue;
            uint32_t vals[NG_MAX_FIELDS];
            char err[200];
            Json lj;
            json_init(&lj);
            if (parse_packet(&pl.pol, s, vals, err, sizeof err) != 0) {
                json_obj(&lj);
                json_kbool(&lj, "ok", 0);
                json_kstr(&lj, "input", s);
                json_kstr(&lj, "error", err);
                json_end_obj(&lj);
            } else {
                emit_classify_json(&lj, &pl, vals, s);
            }
            print_json_and_free(&lj);
        }
    } else if (is_verify) {
        emit_verify_json(&j, &pl, a.n, a.seed);
        print_json_and_free(&j);
    } else {
        int tl = 0;
        char *dot = NULL;
        if (strcmp(a.stage, "nfa") == 0) dot = dot_nfa(&pl.c.nfa, &pl.pol, &pl.pt, 0, &tl);
        else if (strcmp(a.stage, "dfa") == 0) dot = dot_dfa(&pl.c.dfa, &pl.pol, &pl.pt, 0, &tl, "D", 1);
        else if (a.min_mode == MIN_BY_RULE) dot = dot_dfa(&pl.min_rule, &pl.pol, &pl.pt, 0, &tl, "M", 1);
        else dot = dot_dfa(&pl.c.min, &pl.pol, &pl.pt, 0, &tl, "M", 0);
        fputs(dot, stdout);
        free(dot);
    }
    json_free(&j);
    pipeline_free(&pl);
    return rc;
}
