/*
 * oracle.c -- Linear first-match-wins evaluator.
 *
 * Algorithm.  Scan the rules in priority order and return the action of the
 * first rule whose every field range contains the packet's value; if none
 * matches, return the default action.  This is the direct operational
 * semantics of a firewall policy, written as simply as possible so it can
 * serve as an independent reference ("test oracle") for the automata.  It
 * is used only by verification (verify, tests, the classify cross-check),
 * never to produce a decision shown as the compiler's own result.
 *
 * Complexity: O(R * F) per packet.
 *
 * Compiler-design concept: a reference interpreter used to validate a
 * compiler (differential testing of compiled code against an interpreter).
 */
#include "oracle.h"

int oracle_eval(const Policy *p, const uint32_t *vals, int *winner) {
    for (int i = 0; i < p->nrules; i++) {
        int k = 0;
        while (k < p->nfields && rule_field_contains(&p->rules[i], k, vals[k])) k++;
        if (k == p->nfields) {
            if (winner) *winner = i;
            return p->rules[i].action;
        }
    }
    if (winner) *winner = -1;
    return p->default_action;
}
