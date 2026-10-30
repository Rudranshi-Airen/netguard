/*
 * classify.c -- Packet classification with an explanation.
 *
 * Algorithm.
 *   1. Map each field value to its alphabet symbol (binary search in the
 *      field's partition: O(log R) per field).
 *   2. Run the minimized DFA on the symbol string: one table lookup per
 *      field, O(F).  Its final output is the decision.
 *   3. Run the unminimized DFA on the same string: its final state carries
 *      `matched` (all rules matching the packet) and `winner` (the first).
 *   4. For every rule before the winner (every rule, if the DEFAULT
 *      decided), report the first field whose range does not contain the
 *      value, e.g.  R1: dst_port 443 not in [22,22].
 *   5. Cross-check against the linear oracle (independent reference).
 * The trace lists, per field: value, symbol, interval and the DFA states
 * before and after the transition.
 *
 * Complexity: O(F log R) to classify, O(R * F) for the explanation.
 *
 * Compiler-design concept: running the generated automaton (the "object
 * code" of the policy) -- table-driven DFA simulation, as in a generated
 * scanner -- plus a trace for explainability.
 */
#include "classify.h"
#include "oracle.h"
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

void classify_packet(Classification *c, const Policy *p, const Partition *pt, const DFA *min,
                     const DFA *dfa, const uint32_t *vals) {
    memset(c, 0, sizeof *c);
    int ms[NG_MAX_FIELDS + 1], ds[NG_MAX_FIELDS + 1];
    c->min_final = dfa_run(min, pt, vals, ms);
    c->dfa_final = dfa_run(dfa, pt, vals, ds);
    c->decision = min->output[c->min_final];
    c->winner = dfa->winner[c->dfa_final];
    c->matched = dfa->matched[c->dfa_final];
    for (int k = 0; k < p->nfields; k++) {
        TraceStep *t = &c->trace[k];
        t->field = k;
        t->value = vals[k];
        t->sym = partition_lookup(pt, k, vals[k]);
        t->gsym = pt->f[k].offset + t->sym;
        t->iv = pt->f[k].iv[t->sym];
        t->from = ms[k];
        t->to = ms[k + 1];
        t->dfa_from = ds[k];
        t->dfa_to = ds[k + 1];
    }
    int upto = c->winner >= 0 ? c->winner : p->nrules;
    for (int i = 0; i < upto; i++)
        for (int k = 0; k < p->nfields; k++)
            if (!rule_field_contains(&p->rules[i], k, vals[k])) {
                c->fails[c->nfails++] = (Failure){i, k};
                break;
            }
    c->oracle_decision = oracle_eval(p, vals, &c->oracle_winner);
}

static int parse_value(const Policy *p, int k, const char *v, uint32_t *out) {
    if (str_ieq(p->fields[k].name, "proto")) {
        if (str_ieq(v, "TCP")) { *out = 6; return 0; }
        if (str_ieq(v, "UDP")) { *out = 17; return 0; }
        if (str_ieq(v, "ICMP")) { *out = 1; return 0; }
    }
    if (strchr(v, '.')) return ip_parse(v, out);
    return u32_parse(v, out);
}

int parse_packet(const Policy *p, const char *text, uint32_t *vals, char *err, int errcap) {
    int seen[NG_MAX_FIELDS] = {0};
    const char *s = text;
    for (;;) {
        while (*s && (isspace((unsigned char)*s) || *s == ',')) s++;
        if (!*s) break;
        char key[64], val[64];
        int n = 0;
        while (*s && *s != '=' && !isspace((unsigned char)*s) && n < 63) key[n++] = *s++;
        key[n] = '\0';
        if (*s != '=') {
            snprintf(err, (size_t)errcap, "expected field=value, got '%s'", key);
            return -1;
        }
        s++;
        n = 0;
        while (*s && !isspace((unsigned char)*s) && *s != ',' && n < 63) val[n++] = *s++;
        val[n] = '\0';
        int k = -1;
        for (int f = 0; f < p->nfields; f++)
            if (str_ieq(p->fields[f].name, key)) k = f;
        if (k < 0) {
            snprintf(err, (size_t)errcap, "unknown field '%s'", key);
            return -1;
        }
        uint32_t v = 0;
        if (parse_value(p, k, val, &v) != 0) {
            snprintf(err, (size_t)errcap, "bad value '%s' for field %s", val, key);
            return -1;
        }
        if (v < p->fields[k].domain.lo || v > p->fields[k].domain.hi) {
            snprintf(err, (size_t)errcap, "value %s of %s is outside its domain %u..%u", val, key,
                     (unsigned)p->fields[k].domain.lo, (unsigned)p->fields[k].domain.hi);
            return -1;
        }
        vals[k] = v;
        seen[k] = 1;
    }
    for (int k = 0; k < p->nfields; k++)
        if (!seen[k]) {
            snprintf(err, (size_t)errcap, "missing field '%s'", p->fields[k].name);
            return -1;
        }
    return 0;
}
