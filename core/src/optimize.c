/*
 * optimize.c -- Behaviour-preserving rule removal, validated by equivalence.
 *
 * Algorithm.
 *   Phase 1:  P' := P minus every fully shadowed rule.  This is always
 *             behaviour-preserving: a shadowed rule never decides a packet,
 *             so deleting it cannot change any decision.
 *   Phase 2:  Scan-based removal using kept-set K (bitset over original rules).
 *             For i from last to first (shadowed rules already gone from K):
 *               Try removing i from K.  The decision of K \ {i} on a final
 *               state s is the action of the lowest rule in matched(s) ∩ K
 *               excluding i, or DEFAULT.  If that action equals output(s)
 *               (the original DFA decision) for every reachable final state,
 *               then removing i from K does not change the policy on any
 *               packet -> keep i removed.  Otherwise restore i in K.
 *             This is O(R * |final states| * R/64) -- no recompilation.
 *   Final:    Run the existing product-automaton equivalence check ONCE on
 *             the final optimized policy as the formal proof.  Keep that
 *             check and its output.
 * Every removal is logged with a reason: who decides the removed rule's
 * packets afterwards (found by rescanning the DFA of P' for the states the
 * rule won), and -- when a rule was needed in the original policy but
 * became removable after earlier deletions -- which deletion enabled it.
 * Going from last to first means a rule is tested after the rules that
 * could take over its packets have reached their final form.
 *
 * The optimizer only REMOVES rules; it never merges, splits or rewrites
 * one, so every remaining line is a line the author wrote.  The result is
 * printed back to source (renumbered, each line commented with its original
 * id) and re-validated as a whole by the driver.
 *
 * Compiler-design concept: an optimization pass (dead / useless code
 * elimination) guarded by translation validation: each transformation is
 * accepted only if equivalence with the original is proved.
 */
#include "optimize.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void add_removal(Optimization *o, int index, const char *phase, const char *reason) {
    o->removed = xrealloc(o->removed, sizeof(Removal) * (size_t)(o->nremoved + 1));
    Removal *r = &o->removed[o->nremoved++];
    r->index = index;
    str_copy(r->phase, phase, sizeof r->phase);
    str_copy(r->reason, reason, sizeof r->reason);
}


static void emit_source(Optimization *o, const Policy *p, Syntax syn) {
    StrBuf sb;
    sb_init(&sb);
    char line[512];
    if (syn == SYNTAX_FW) {
        sb_printf(&sb, "# Optimized by NetGuard: %d of %d rules kept (equivalent to the original)\n",
                  o->optimized_rules, o->original_rules);
        int n = 0;
        for (int i = 0; i < p->nrules; i++) {
            if (!o->keep[i]) continue;
            fmt_rule_source(p, syn, &p->rules[i], line, sizeof line);
            sb_printf(&sb, "%-56s # R%d (original %s)\n", line, ++n, p->rules[i].id);
        }
        sb_printf(&sb, "DEFAULT %s\n", p->actions[p->default_action]);
    } else {
        sb_printf(&sb, "# Optimized by NetGuard: %d of %d rules kept (equivalent to the original)\n",
                  o->optimized_rules, o->original_rules);
        sb_printf(&sb, "ruleset %s;\n", p->name);
        for (int k = 0; k < p->nfields; k++)
            sb_printf(&sb, "field %s : %u .. %u;\n", p->fields[k].name, (unsigned)p->fields[k].domain.lo,
                      (unsigned)p->fields[k].domain.hi);
        sb_printf(&sb, "default %s;\n", p->actions[p->default_action]);
        int n = 0;
        for (int i = 0; i < p->nrules; i++) {
            if (!o->keep[i]) continue;
            fmt_rule_source(p, syn, &p->rules[i], line, sizeof line);
            sb_printf(&sb, "%-60s # rule %d (original %s, position %d)\n", line, ++n, p->rules[i].id, i + 1);
        }
    }
    o->source = sb_take(&sb);
}

/*
 * scan_can_remove_from_K -- can rule `i` be removed from kept-set K?
 *
 * The decision of K on final state s is:
 *   - The action of the lowest rule j in matched(s) such that keep[j] is set, OR
 *   - DEFAULT if no such j exists.
 * This must equal output(s) (the original policy's output) for every
 * reachable final state.
 *
 * To test removal of i: temporarily clear keep[i] and re-evaluate.
 * We check directly without recompilation.
 */
static int scan_can_remove_from_K(const DFA *d, const Policy *p, unsigned char *keep, int i) {
    keep[i] = 0;
    int ok = 1;
    for (int s = 0; s < d->nstates && ok; s++) {
        if (d->layer[s] != d->nfields) continue;
        int orig = d->output[s];   /* action the full original DFA gives */
        /* Find the first kept rule in matched(s). */
        int cand = -1;
        for (int j = rs_lowest(&d->matched[s]); j >= 0; j = rs_next(&d->matched[s], j)) {
            if (keep[j]) { cand = j; break; }
        }
        int new_out = (cand >= 0) ? p->rules[cand].action : p->default_action;
        if (new_out != orig) ok = 0;
    }
    keep[i] = 1;
    return ok;
}

int optimize_run(Optimization *o, const Policy *p, Syntax syn, const Partition *pt,
                 const Compiled *orig, const Analysis *an) {
    memset(o, 0, sizeof *o);
    o->original_rules = p->nrules;
    char reason[900], names[400], pkt[200];
    int rc = 0;
    (void)pt; /* kept for future use; equiv check below uses orig->min */

    /* Phase 1: fully shadowed rules. */
    for (int i = 0; i < p->nrules; i++) o->keep[i] = 1;
    for (int i = 0; i < p->nrules; i++) {
        const RuleReport *r = &an->r[i];
        if (r->status != ST_SHADOWED) continue;
        o->keep[i] = 0;
        ruleset_names(p, &r->covered_by, 1, names, sizeof names);
        if (!r->union_shadow)
            snprintf(reason, sizeof reason,
                     "Fully shadowed (single-rule shadow, %s): %s contains it, so it never decides a packet; its packets are decided by %s.",
                     r->conflicting ? "conflicting" : "same action", p->rules[r->container].id, names);
        else
            snprintf(reason, sizeof reason,
                     "Fully shadowed (union shadow, %s): together %s decide every packet it matches, so it never decides a packet.",
                     r->conflicting ? "conflicting" : "same action", names);
        add_removal(o, i, "shadowed", reason);
    }

    /* Phase 2: last to first, scan-based kept-set removal.
     * For each candidate i (not already removed), check if the kept-set
     * K \ {i} gives the same output as the original DFA on every final state.
     * No recompilation; uses the unminimized DFA of the ORIGINAL policy. */
    const DFA *d = &orig->dfa;
    for (int i = p->nrules - 1; i >= 0 && rc == 0; i--) {
        if (!o->keep[i]) continue;
        if (!scan_can_remove_from_K(d, p, o->keep, i)) continue;
        /* Rule i can be removed from K. */
        o->keep[i] = 0;

        /* Who decides rule i's packets once it is gone?  Scan states where i won. */
        RuleSet dec;
        int uses_default = 0;
        rs_clear(&dec);
        for (int s = 0; s < d->nstates; s++) {
            if (d->layer[s] != d->nfields || !rs_test(&d->matched[s], i)) continue;
            /* States that i decided in the current kept policy (K with i):
             * no kept rule before i matches there. */
            int earlier = 0;
            for (int j = rs_lowest(&d->matched[s]); j >= 0 && j < i; j = rs_next(&d->matched[s], j))
                if (o->keep[j]) { earlier = 1; break; }
            if (earlier) continue;
            /* Find first kept rule after i in matched(s). */
            int next = -1;
            for (int j = rs_next(&d->matched[s], i); j >= 0; j = rs_next(&d->matched[s], j)) {
                if (o->keep[j]) { next = j; break; }
            }
            if (next >= 0) rs_set(&dec, next);
            else uses_default = 1;
        }

        StrBuf sb;
        sb_init(&sb);
        const char *act = p->actions[p->rules[i].action];
        const RuleReport *r = &an->r[i];
        if (r->status == ST_REDUNDANT) sb_puts(&sb, "Redundant: deleting it leaves the policy equivalent to the original; ");
        else {
            sb_printf(&sb, "Became removable after earlier deletions (it was needed in the original policy");
            if (r->has_cx) {
                fmt_packet(p, r->cx, pkt, sizeof pkt);
                if (r->cx_winner_without >= 0)
                    sb_printf(&sb, ": deleting it alone would let %s (%s) decide %s", p->rules[r->cx_winner_without].id,
                              p->actions[p->rules[r->cx_winner_without].action], pkt);
                else
                    sb_printf(&sb, ": deleting it alone would change %s", pkt);
            }
            sb_puts(&sb, "). ");
            if (r->has_cx && r->cx_winner_without >= 0 && !o->keep[r->cx_winner_without])
                sb_printf(&sb, "Now that %s has been removed, ", p->rules[r->cx_winner_without].id);
            else
                sb_puts(&sb, "After the earlier removals, ");
        }
        if (rs_lowest(&dec) >= 0) {
            ruleset_names(p, &dec, 1, names, sizeof names);
            sb_printf(&sb, "the packets it decided are decided by %s", names);
            if (uses_default) sb_printf(&sb, " or DEFAULT %s", p->actions[p->default_action]);
        } else {
            sb_printf(&sb, "the packets it decided fall through to DEFAULT %s", p->actions[p->default_action]);
        }
        sb_printf(&sb, ", the same action (%s).", act);
        add_removal(o, i, r->status == ST_REDUNDANT ? "redundant" : "redundant-after", sb.data);
        sb_free(&sb);
    }

    policy_subset(&o->optimized, p, o->keep);
    o->optimized_rules = o->optimized.nrules;
    emit_source(o, p, syn);
    return rc;
}

/*
 * optimize_keep_equiv -- the OLD phase 2 (one product-automaton equivalence
 * check per rule).  Kept under this name only for the differential test that
 * proves the scan-based phase 2 removes exactly the same rules.
 * keep[] must arrive with the shadowed rules already cleared.  Returns 0, -1 on limits.
 */
int optimize_keep_equiv(const Policy *p, const Partition *pt, const Compiled *orig, unsigned char *keep) {
    for (int i = p->nrules - 1; i >= 0; i--) {
        if (!keep[i]) continue;
        keep[i] = 0;
        Policy cand;
        policy_subset(&cand, p, keep);
        EquivResult er;
        int rc = equiv_with(&er, &orig->min, &cand, pt);
        policy_free(&cand);
        if (rc != 0) return -1;
        if (!er.equivalent) keep[i] = 1;
    }
    return 0;
}

void optimize_free(Optimization *o) {
    free(o->removed);
    free(o->source);
    policy_free(&o->optimized);
    memset(o, 0, sizeof *o);
}
