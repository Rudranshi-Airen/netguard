/*
 * analysis.c -- Shadowing and redundancy analysis (a separate pass over the
 * UNMINIMIZED DFA produced by the subset construction).
 *
 * Why the unminimized DFA: each of its final-layer states records the full
 * set `matched` of rules accepting there and the `winner` (lowest index).
 * Every reachable final-layer state is reached by at least one symbol
 * string, and every symbol is a non-empty interval, so every such state
 * stands for at least one real packet.  Scanning those states therefore
 * tells, exactly and without enumerating packets, which rules can ever
 * decide a packet.  (Minimization is a different, independent step: it
 * merges states and forgets `matched`; it plays no part in this analysis.)
 *
 * Algorithm, for each rule i:
 *   1. Scan the final-layer states.  If i is in matched: i wins there when
 *      winner == i, otherwise it loses to winner (record it in beaten_by).
 *   2. Fully shadowed: i is matched somewhere but never wins.  Its covering
 *      set is the union of the winners where it is matched.
 *        - conflicting if a covering rule has a different action (high
 *          severity: the rule's intent is silently overridden), else
 *          same-action (dead code);
 *        - single-rule shadow if one earlier rule contains i field by field
 *          (checked directly on the IR ranges), otherwise union shadow
 *          (only a combination of earlier rules covers it).
 *   3. Redundant (fast scan, no recompilation): i wins somewhere.
 *      For each final state s where winner(s) == i, find the next rule in
 *      matched(s) after i (via deciders_after_removal).  If in EVERY such
 *      state the next decider's action equals action(i) (or the DEFAULT
 *      equals action(i) when there is no next rule), then i is redundant.
 *      This is exact: every reachable final state stands for at least one
 *      real packet, and the DFA decision is output(s) regardless of whether
 *      i is present.
 *   4. Partially overlapped: i wins in some states and loses in others to a
 *      rule that is not redundant.  (A loss to a redundant rule is benign:
 *      by definition deleting that rule changes no decision; such rules are
 *      still listed in beaten_by and mentioned in the explanation.)
 *   5. Otherwise ok.
 * Each status comes with a concrete example packet rebuilt from the DFA's
 * BFS tree (dfa_witness) and a plain-English explanation.
 *
 * Complexity: O(|final states| * R / 64) for the scan, zero recompilations
 * for redundancy detection.  Contrast with the old approach: one full
 * compile-and-compare per candidate rule.
 *
 * Compiler-design concept: static (dataflow-style) analysis on the
 * compiler's own intermediate automaton -- detecting dead code (shadowed
 * rules) and useless code (redundant rules) before optimization.
 */
#include "analysis.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *status_name(RuleStatus s) {
    static const char *n[] = {"ok", "shadowed", "partial", "redundant"};
    return n[s];
}

void ruleset_names(const Policy *p, const RuleSet *s, int with_action, char *buf, int n) {
    StrBuf sb;
    sb_init(&sb);
    int first = 1;
    for (int j = rs_lowest(s); j >= 0; j = rs_next(s, j)) {
        if (with_action) sb_printf(&sb, "%s%s (%s)", first ? "" : ", ", p->rules[j].id, p->actions[p->rules[j].action]);
        else sb_printf(&sb, "%s%s", first ? "" : ", ", p->rules[j].id);
        first = 0;
    }
    str_copy(buf, sb.data ? sb.data : "", (size_t)n);
    sb_free(&sb);
}

void deciders_after_removal(const DFA *d, int removed, RuleSet *out, int *uses_default) {
    rs_clear(out);
    *uses_default = 0;
    for (int s = 0; s < d->nstates; s++) {
        if (d->layer[s] != d->nfields || d->winner[s] != removed) continue;
        int next = rs_next(&d->matched[s], removed);
        if (next >= 0) rs_set(out, next);
        else *uses_default = 1;
    }
}

/* Does rule j contain rule i on every field? */
static int contains(const Policy *p, int j, int i) {
    for (int k = 0; k < p->nfields; k++)
        if (p->rules[j].cond[k].lo > p->rules[i].cond[k].lo || p->rules[j].cond[k].hi < p->rules[i].cond[k].hi)
            return 0;
    return 1;
}

static void decider_text(const Policy *p, int winner, char *buf, size_t n) {
    if (winner >= 0) snprintf(buf, n, "%s (%s)", p->rules[winner].id, p->actions[p->rules[winner].action]);
    else snprintf(buf, n, "DEFAULT (%s)", p->actions[p->default_action]);
}

/* First-match evaluation of p with rule `skip` deleted. */
static int eval_without(const Policy *p, int skip, const uint32_t *vals, int *winner) {
    for (int i = 0; i < p->nrules; i++) {
        if (i == skip) continue;
        int k = 0;
        while (k < p->nfields && rule_field_contains(&p->rules[i], k, vals[k])) k++;
        if (k == p->nfields) { *winner = i; return p->rules[i].action; }
    }
    *winner = -1;
    return p->default_action;
}

static void explain(const Policy *p, RuleReport *r, int i) {
    const Rule *ru = &p->rules[i];
    const char *act = p->actions[ru->action];
    char pkt[200], names[400], dec[80];
    StrBuf sb;
    sb_init(&sb);
    if (r->has_example) fmt_packet(p, r->example, pkt, sizeof pkt);
    else pkt[0] = '\0';

    switch (r->status) {
    case ST_SHADOWED:
        ruleset_names(p, &r->covered_by, 1, names, sizeof names);
        sb_printf(&sb, "%s never decides any packet: every packet it matches is matched first by an earlier rule. ", ru->id);
        if (!r->union_shadow)
            sb_printf(&sb, "%s alone contains %s field by field (single-rule shadow); on the DFA the packets of %s are decided by %s. ",
                      p->rules[r->container].id, ru->id, ru->id, names);
        else
            sb_printf(&sb, "No single earlier rule contains it, but together %s cover all of its packets (union shadow). ", names);
        if (r->conflicting)
            sb_printf(&sb, "At least one of them has a different action than %s's %s, so the intent of %s is silently overridden: likely a misconfiguration. ",
                      ru->id, act, ru->id);
        else
            sb_printf(&sb, "They all have the same action (%s), so %s is dead code and can be deleted. ", act, ru->id);
        if (r->has_example) {
            decider_text(p, r->example_winner, dec, sizeof dec);
            sb_printf(&sb, "Example: %s matches %s but is decided by %s.", pkt, ru->id, dec);
        }
        break;
    case ST_REDUNDANT:
        sb_printf(&sb, "%s does decide some packets, but deleting it alone changes no decision: ", ru->id);
        if (rs_lowest(&r->deciders) >= 0) {
            ruleset_names(p, &r->deciders, 1, names, sizeof names);
            sb_printf(&sb, "those packets would then be decided by %s", names);
            if (r->default_decides) sb_printf(&sb, " or by DEFAULT %s", p->actions[p->default_action]);
        } else {
            sb_printf(&sb, "those packets would then fall through to DEFAULT %s", p->actions[p->default_action]);
        }
        sb_printf(&sb, ", which gives the same action (%s). ", act);
        if (r->has_example) sb_printf(&sb, "Example packet decided by %s: %s.", ru->id, pkt);
        break;
    case ST_PARTIAL:
        ruleset_names(p, &r->beaten_by, 1, names, sizeof names);
        sb_printf(&sb, "%s decides some of its packets, but others are taken first by earlier rule(s) %s. ", ru->id, names);
        if (r->conflicting)
            sb_printf(&sb, "Some of those rules have a different action, so part of %s's %s intent is overridden. ", ru->id, act);
        else
            sb_printf(&sb, "They have the same action, so the overlap is harmless but makes the policy harder to read. ");
        if (r->has_example) {
            decider_text(p, r->example_winner, dec, sizeof dec);
            sb_printf(&sb, "Example: %s matches %s but is decided by %s.", pkt, ru->id, dec);
        }
        break;
    case ST_OK:
        sb_printf(&sb, "%s decides every packet it matches", ru->id);
        if (rs_lowest(&r->beaten_by) >= 0) {
            ruleset_names(p, &r->beaten_by, 0, names, sizeof names);
            sb_printf(&sb, ", except for packets taken first by %s; those rules are redundant, so the overlap changes no decision", names);
        }
        sb_printf(&sb, ". Deleting it would change some decisions");
        if (r->has_cx) {
            fmt_packet(p, r->cx, pkt, sizeof pkt);
            decider_text(p, r->cx_winner_without, dec, sizeof dec);
            sb_printf(&sb, " (e.g. %s would be decided by %s instead of %s)", pkt, dec, act);
        }
        sb_puts(&sb, ", so it is needed.");
        break;
    }
    str_copy(r->explanation, sb.data ? sb.data : "", sizeof r->explanation);
    sb_free(&sb);
}

/*
 * scan_redundant -- exact, no-recompilation redundancy check.
 *
 * Rule i is redundant iff, for every final state s where winner(s)==i,
 * the next rule in matched(s) after i (or DEFAULT if there is none) has
 * the same action as rule i.
 *
 * Fills r->deciders and r->default_decides as a side effect.
 * Returns 1 if redundant, 0 if not.
 */
static int scan_redundant(const DFA *d, const Policy *p, int i, RuleReport *r) {
    int action_i = p->rules[i].action;
    rs_clear(&r->deciders);
    r->default_decides = 0;
    int any_win = 0;

    for (int s = 0; s < d->nstates; s++) {
        if (d->layer[s] != d->nfields || d->winner[s] != i) continue;
        any_win = 1;
        /* next rule in matched after i */
        int next = rs_next(&d->matched[s], i);
        if (next >= 0) {
            rs_set(&r->deciders, next);
            if (p->rules[next].action != action_i) return 0;   /* different action -> not redundant */
        } else {
            r->default_decides = 1;
            if (p->default_action != action_i) return 0;        /* DEFAULT differs -> not redundant */
        }
    }
    return any_win;   /* only redundant if it wins at least one state */
}

/*
 * analysis_redundancy_equiv_check -- OLD recompile-per-rule approach.
 * Kept under this name for the differential C test in P1-a only.
 * Returns 1 if rule i is redundant by equiv_with, 0 if not, -1 on error.
 */
int analysis_redundancy_equiv_check(const Policy *p, const Partition *pt, const Compiled *c, int i) {
    unsigned char *keep = xmalloc((size_t)(p->nrules ? p->nrules : 1));
    memset(keep, 1, (size_t)p->nrules);
    keep[i] = 0;
    Policy without;
    policy_subset(&without, p, keep);
    free(keep);
    EquivResult er;
    int rc = equiv_with(&er, &c->min, &without, pt);
    policy_free(&without);
    if (rc != 0) return -1;
    return er.equivalent ? 1 : 0;
}

int analysis_run(Analysis *a, const Policy *p, const Partition *pt, const Compiled *c) {
    const DFA *d = &c->dfa;
    memset(a, 0, sizeof *a);
    a->nrules = p->nrules;
    a->r = xcalloc((size_t)(p->nrules ? p->nrules : 1), sizeof(RuleReport));
    int rc = 0;

    /* Step 1: scan the final-layer states once. */
    for (int i = 0; i < p->nrules; i++) {
        a->r[i].container = -1;
        a->r[i].example_winner = -1;
        a->r[i].cx_winner_without = -1;
    }
    for (int s = 0; s < d->nstates; s++) {
        if (d->layer[s] != d->nfields) continue;
        int w = d->winner[s];
        for (int i = rs_lowest(&d->matched[s]); i >= 0; i = rs_next(&d->matched[s], i)) {
            RuleReport *r = &a->r[i];
            if (i == w) {
                r->win_states++;
            } else {
                r->lose_states++;
                rs_set(&r->beaten_by, w);
            }
        }
    }

    /* Step 2: shadowed rules. */
    for (int i = 0; i < p->nrules; i++) {
        RuleReport *r = &a->r[i];
        if (r->win_states > 0) continue;
        r->status = ST_SHADOWED;
        r->covered_by = r->beaten_by;
        for (int j = rs_lowest(&r->covered_by); j >= 0; j = rs_next(&r->covered_by, j))
            if (p->rules[j].action != p->rules[i].action) r->conflicting = 1;
        for (int j = 0; j < i && r->container < 0; j++)
            if (contains(p, j, i)) r->container = j;
        r->union_shadow = r->container < 0;
    }

    /* Step 3: redundancy -- fast DFA scan, no recompilation.
     * For each rule i that wins somewhere: scan states where i wins;
     * if every such state's "next decider after i" has the same action,
     * i is redundant.  collect counterexample (cx) for ST_OK explanation. */
    for (int i = 0; i < p->nrules && rc == 0; i++) {
        RuleReport *r = &a->r[i];
        if (r->status == ST_SHADOWED) continue;
        r->removal_checked = 1;
        if (scan_redundant(d, p, i, r)) {
            r->status = ST_REDUNDANT;
        } else {
            /* Find a counterexample: a state where i wins and the alternative
             * has a different action (for the ST_OK explanation). */
            for (int s = 0; s < d->nstates && !r->has_cx; s++) {
                if (d->layer[s] != d->nfields || d->winner[s] != i) continue;
                int next = rs_next(&d->matched[s], i);
                int alt_action = (next >= 0) ? p->rules[next].action : p->default_action;
                if (alt_action == p->rules[i].action) continue;
                /* This state is a distinguishing witness. */
                for (int k = 0; k < p->nfields; k++) r->cx[k] = pt->f[k].iv[0].lo;
                dfa_witness(d, pt, s, r->cx);
                eval_without(p, i, r->cx, &r->cx_winner_without);
                r->has_cx = 1;
            }
        }
    }

    /* Step 4: partial overlaps (losses to non-redundant rules). */
    for (int i = 0; i < p->nrules; i++) {
        RuleReport *r = &a->r[i];
        if (r->status != ST_OK) continue;
        for (int j = rs_lowest(&r->beaten_by); j >= 0; j = rs_next(&r->beaten_by, j)) {
            if (a->r[j].status == ST_REDUNDANT) continue;
            r->status = ST_PARTIAL;
            if (p->rules[j].action != p->rules[i].action) r->conflicting = 1;
        }
    }

    /* Examples, subtype, severity, explanation. */
    for (int i = 0; i < p->nrules; i++) {
        RuleReport *r = &a->r[i];
        for (int s = 0; s < d->nstates && !r->has_example; s++) {
            if (d->layer[s] != d->nfields || !rs_test(&d->matched[s], i)) continue;
            int w = d->winner[s];
            int want = (r->status == ST_SHADOWED) ? 1
                     : (r->status == ST_PARTIAL) ? (w != i && a->r[w].status != ST_REDUNDANT)
                     : (w == i);
            if (!want) continue;
            for (int k = 0; k < p->nfields; k++) r->example[k] = pt->f[k].iv[0].lo;
            dfa_witness(d, pt, s, r->example);
            r->example_winner = w;
            r->has_example = 1;
        }
        switch (r->status) {
        case ST_SHADOWED:
            snprintf(r->subtype, sizeof r->subtype, "%s, %s", r->union_shadow ? "union shadow" : "single-rule shadow",
                     r->conflicting ? "conflicting" : "same-action");
            r->severity = r->conflicting ? "high" : "medium";
            break;
        case ST_PARTIAL:
            snprintf(r->subtype, sizeof r->subtype, "%s", r->conflicting ? "conflicting overlap" : "same-action overlap");
            r->severity = r->conflicting ? "medium" : "low";
            break;
        case ST_REDUNDANT:
            snprintf(r->subtype, sizeof r->subtype, "%s",
                     rs_lowest(&r->deciders) >= 0 ? "covered by a later rule" : "covered by DEFAULT");
            r->severity = "low";
            break;
        case ST_OK:
            r->subtype[0] = '\0';
            r->severity = "none";
            break;
        }
        explain(p, r, i);
        a->count[r->status]++;
        if (r->conflicting) a->conflicting++;
        if (strcmp(r->severity, "high") == 0) a->high++;
    }
    return rc;
}

void analysis_free(Analysis *a) {
    free(a->r);
    memset(a, 0, sizeof *a);
}
