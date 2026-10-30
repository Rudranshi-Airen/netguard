/*
 * compare.c -- Equivalence of two independently written policies
 * (the `netguard equiv ORIGINAL SUGGESTED` command).
 *
 * Algorithm.
 *   1. Parse both sources with the same front end (all diagnostics kept,
 *      with line:col, separately for each file).
 *   2. Check that they are comparable: the same fields, in the same order,
 *      with the same domains (always true for .fw).
 *   3. Put both on ONE action table, by action NAME: the .ng front end
 *      numbers actions in order of first appearance, so the same name can
 *      have different indices in two files.  B's rules and default are
 *      remapped into A's table (new names are appended).
 *   4. equiv_policies(): both policies are compiled over the partition of
 *      A u B (a common refinement of both alphabets) to action-minimized
 *      complete DFAs, and the product automaton is explored breadth-first.
 *      A reachable pair with different outputs yields the shortest
 *      distinguishing symbol string, turned into a concrete packet.
 *   5. The counterexample is re-evaluated with the linear oracle to report
 *      which rule decides it in each policy.
 * The check is a proof: "equivalent" means the two policies decide every
 * one of the 2^(sum of field widths) packets identically.
 *
 * Complexity: parsing O(T); equivalence O(|A| * |B| * |Sigma|) worst case.
 *
 * Compiler-design concept: translation validation -- an untrusted
 * transformation (here: a rewrite proposed by an AI model) is accepted only
 * after the compiler proves it preserves the program's semantics.
 */
#include "compare.h"
#include "oracle.h"
#include "parser_fw.h"
#include "parser_ng.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

static int parse(const char *src, Syntax syn, Policy *p, DiagList *d) {
    diag_init(d);
    if (syn == SYNTAX_FW) return parse_fw(src, p, d, NULL, NULL);
    return parse_ng(src, p, d, NULL, NULL);
}

int compare_sources(Compare *c, const char *src_a, const char *src_b, Syntax syn) {
    memset(c, 0, sizeof *c);
    c->syntax = syn;
    c->winner_a = c->winner_b = -1;
    c->parsed_a = parse(src_a, syn, &c->a, &c->diag_a) == 0;
    c->parsed_b = parse(src_b, syn, &c->b, &c->diag_b) == 0;
    if (!c->parsed_a || !c->parsed_b) {
        snprintf(c->error, sizeof c->error, "%s has errors", !c->parsed_a ? "the original policy" : "the suggested policy");
        return 1;
    }
    if (c->a.nfields != c->b.nfields) {
        snprintf(c->error, sizeof c->error, "the policies declare different numbers of fields (%d vs %d)",
                 c->a.nfields, c->b.nfields);
        return 1;
    }
    for (int k = 0; k < c->a.nfields; k++) {
        const FieldDecl *fa = &c->a.fields[k], *fb = &c->b.fields[k];
        if (strcmp(fa->name, fb->name) != 0 || fa->domain.lo != fb->domain.lo || fa->domain.hi != fb->domain.hi) {
            snprintf(c->error, sizeof c->error,
                     "field %d differs: '%s' %u..%u in the original, '%s' %u..%u in the suggestion", k + 1, fa->name,
                     (unsigned)fa->domain.lo, (unsigned)fa->domain.hi, fb->name, (unsigned)fb->domain.lo,
                     (unsigned)fb->domain.hi);
            return 1;
        }
    }
    /* One action table, by name. */
    int map[NG_MAX_ACTIONS];
    for (int x = 0; x < c->b.nactions; x++) {
        map[x] = policy_intern_action(&c->a, c->b.actions[x]);
        if (map[x] < 0) {
            snprintf(c->error, sizeof c->error, "too many distinct actions across both policies (limit %d)", NG_MAX_ACTIONS);
            return 1;
        }
    }
    for (int i = 0; i < c->b.nrules; i++) c->b.rules[i].action = map[c->b.rules[i].action];
    c->b.default_action = map[c->b.default_action];
    c->b.nactions = c->a.nactions;
    memcpy(c->b.actions, c->a.actions, sizeof c->a.actions);

    if (equiv_policies(&c->er, &c->a, &c->b) != 0) {
        snprintf(c->error, sizeof c->error, "the policies exceed the automaton size limits");
        return -1;
    }
    c->compared = 1;
    if (c->er.has_counterexample) {
        oracle_eval(&c->a, c->er.packet, &c->winner_a);
        oracle_eval(&c->b, c->er.packet, &c->winner_b);
    }
    return 0;
}

void compare_free(Compare *c) {
    diag_free(&c->diag_a);
    diag_free(&c->diag_b);
    policy_free(&c->a);
    policy_free(&c->b);
}

static void emit_diag_list(Json *j, const DiagList *d) {
    json_arr(j);
    for (int i = 0; i < d->count; i++) {
        const Diag *g = &d->items[i];
        json_obj(j);
        json_kstr(j, "level", g->level == DIAG_ERROR ? "error" : "warning");
        json_kint(j, "line", g->line);
        json_kint(j, "col", g->col);
        json_kstr(j, "phase", g->phase);
        json_kstr(j, "message", g->message);
        json_kstr(j, "hint", g->hint);
        json_end_obj(j);
    }
    json_end_arr(j);
}

static const char *decider(const Policy *p, int w) { return w >= 0 ? p->rules[w].id : "DEFAULT"; }

void emit_compare_json(Json *j, const Compare *c) {
    json_obj(j);
    json_kbool(j, "ok", c->compared);
    if (c->compared) json_kbool(j, "equivalent", c->er.equivalent);
    else json_knull(j, "equivalent");
    json_kbool(j, "parsed_original", c->parsed_a);
    json_kbool(j, "parsed_suggested", c->parsed_b);
    if (c->error[0]) json_kstr(j, "error", c->error);
    else json_knull(j, "error");
    json_kint(j, "rules_original", c->parsed_a ? c->a.nrules : -1);
    json_kint(j, "rules_suggested", c->parsed_b ? c->b.nrules : -1);
    json_key(j, "counterexample");
    if (c->compared && c->er.has_counterexample) {
        char text[256];
        fmt_packet(&c->a, c->er.packet, text, sizeof text);
        json_obj(j);
        json_key(j, "fields");
        json_obj(j);
        for (int k = 0; k < c->a.nfields; k++) json_ku64(j, c->a.fields[k].name, c->er.packet[k]);
        json_end_obj(j);
        json_kstr(j, "text", text);
        json_kstr(j, "decided_by_original", decider(&c->a, c->winner_a));
        json_kstr(j, "decided_by_suggested", decider(&c->b, c->winner_b));
        json_end_obj(j);
        json_kstr(j, "action_original", c->a.actions[c->er.action_a]);
        json_kstr(j, "action_suggested", c->a.actions[c->er.action_b]);
    } else {
        json_null(j);
        json_knull(j, "action_original");
        json_knull(j, "action_suggested");
    }
    json_kint(j, "product_pairs_explored", c->compared ? c->er.pairs_explored : 0);
    json_key(j, "diagnostics");
    emit_diag_list(j, &c->diag_b);
    json_key(j, "diagnostics_original");
    emit_diag_list(j, &c->diag_a);
    json_end_obj(j);
}
