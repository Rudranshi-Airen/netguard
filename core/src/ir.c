/*
 * ir.c -- Operations on the shared policy IR.
 *
 * Construction, deep copy, rule-subset extraction (used by the optimizer and
 * by the redundancy check, which compile "P minus some rules"), value
 * formatting, and pretty-printing a rule back into canonical source form.
 * Printing back to source is the "unparse" step of a source-to-source
 * compiler: the optimized policy is emitted as .fw / .ng text that the same
 * front end accepts again.  All operations are O(rules * fields).
 */
#include "ir.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void policy_init(Policy *p) {
    memset(p, 0, sizeof *p);
}

void policy_free(Policy *p) {
    free(p->rules);
    p->rules = NULL;
    p->nrules = 0;
}

void policy_add_rule(Policy *p, const Rule *r) {
    p->rules = xrealloc(p->rules, sizeof(Rule) * (size_t)(p->nrules + 1));
    p->rules[p->nrules] = *r;
    p->rules[p->nrules].index = p->nrules;
    p->nrules++;
}

int policy_intern_action(Policy *p, const char *name) {
    for (int i = 0; i < p->nactions; i++)
        if (strcmp(p->actions[i], name) == 0) return i;
    if (p->nactions >= NG_MAX_ACTIONS) return -1;
    str_copy(p->actions[p->nactions], name, NG_NAME_LEN);
    return p->nactions++;
}

void policy_copy(Policy *dst, const Policy *src) {
    *dst = *src;
    dst->rules = NULL;
    if (src->nrules > 0) {
        dst->rules = xmalloc(sizeof(Rule) * (size_t)src->nrules);
        memcpy(dst->rules, src->rules, sizeof(Rule) * (size_t)src->nrules);
    }
}

void policy_subset(Policy *dst, const Policy *src, const unsigned char *keep) {
    *dst = *src;
    dst->rules = NULL;
    dst->nrules = 0;
    for (int i = 0; i < src->nrules; i++)
        if (keep[i]) policy_add_rule(dst, &src->rules[i]);
}

int rule_field_contains(const Rule *r, int k, uint32_t v) {
    return v >= r->cond[k].lo && v <= r->cond[k].hi;
}

int field_is_ip(const Policy *p, int k) {
    size_t n = strlen(p->fields[k].name);
    return n >= 2 && str_ieq(p->fields[k].name + n - 2, "ip");
}

static const char *proto_name(uint32_t v) {
    switch (v) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    default: return NULL;
    }
}

static int field_is_proto(const Policy *p, int k) {
    return str_ieq(p->fields[k].name, "proto");
}

void fmt_value(const Policy *p, int k, uint32_t v, char *buf, int n) {
    if (field_is_ip(p, k)) {
        ip_to_str(v, buf, (size_t)n);
    } else if (field_is_proto(p, k) && proto_name(v)) {
        snprintf(buf, (size_t)n, "%u (%s)", (unsigned)v, proto_name(v));
    } else {
        snprintf(buf, (size_t)n, "%u", (unsigned)v);
    }
}

void fmt_range(const Policy *p, int k, Range r, char *buf, int n) {
    char a[32], b[32];
    if (field_is_ip(p, k)) {
        ip_to_str(r.lo, a, sizeof a);
        ip_to_str(r.hi, b, sizeof b);
    } else {
        snprintf(a, sizeof a, "%u", (unsigned)r.lo);
        snprintf(b, sizeof b, "%u", (unsigned)r.hi);
    }
    snprintf(buf, (size_t)n, "[%s,%s]", a, b);
}

void fmt_packet(const Policy *p, const uint32_t *vals, char *buf, int n) {
    StrBuf sb;
    sb_init(&sb);
    for (int k = 0; k < p->nfields; k++) {
        char v[32];
        if (field_is_ip(p, k)) ip_to_str(vals[k], v, sizeof v);
        else if (field_is_proto(p, k) && proto_name(vals[k])) str_copy(v, proto_name(vals[k]), sizeof v);
        else snprintf(v, sizeof v, "%u", (unsigned)vals[k]);
        sb_printf(&sb, "%s%s=%s", k ? " " : "", p->fields[k].name, v);
    }
    str_copy(buf, sb.data ? sb.data : "", (size_t)n);
    sb_free(&sb);
}

static int is_full(const Policy *p, int k, Range r) {
    return r.lo == p->fields[k].domain.lo && r.hi == p->fields[k].domain.hi;
}

/* Print an IPv4 range as ANY, a single address, a CIDR block or a-b. */
static void fmt_addr(Range r, char *buf, size_t n) {
    char a[16], b[16];
    ip_to_str(r.lo, a, sizeof a);
    if (r.lo == 0 && r.hi == 0xFFFFFFFFu) { str_copy(buf, "ANY", n); return; }
    if (r.lo == r.hi) { str_copy(buf, a, n); return; }
    uint64_t size = (uint64_t)r.hi - r.lo + 1;
    if ((size & (size - 1)) == 0 && (r.lo & (uint32_t)(size - 1)) == 0) {
        int prefix = 32;
        while (size > 1) { size >>= 1; prefix--; }
        snprintf(buf, n, "%s/%d", a, prefix);
        return;
    }
    ip_to_str(r.hi, b, sizeof b);
    snprintf(buf, n, "%s-%s", a, b);
}

void fmt_rule_source(const Policy *p, Syntax syn, const Rule *r, char *buf, int n) {
    StrBuf sb;
    sb_init(&sb);
    if (syn == SYNTAX_FW) {
        char src[40], dst[40];
        Range pr = r->cond[0];
        sb_printf(&sb, "%-5s ", p->actions[r->action]);
        if (is_full(p, 0, pr)) sb_puts(&sb, "ANY ");
        else if (proto_name(pr.lo)) sb_printf(&sb, "%s ", proto_name(pr.lo));
        else sb_printf(&sb, "%u ", (unsigned)pr.lo);
        fmt_addr(r->cond[1], src, sizeof src);
        fmt_addr(r->cond[2], dst, sizeof dst);
        sb_printf(&sb, "FROM %s TO %s", src, dst);
        Range pt = r->cond[3];
        if (!is_full(p, 3, pt)) {
            if (pt.lo == pt.hi) sb_printf(&sb, " PORT %u", (unsigned)pt.lo);
            else sb_printf(&sb, " PORT %u-%u", (unsigned)pt.lo, (unsigned)pt.hi);
        }
    } else {
        sb_printf(&sb, "rule %s : %s when", r->id, p->actions[r->action]);
        int any = 0;
        for (int k = 0; k < p->nfields; k++) {
            if (is_full(p, k, r->cond[k]) && !(k == p->nfields - 1 && !any)) continue;
            if (r->cond[k].lo == r->cond[k].hi)
                sb_printf(&sb, "%s %s == %u", any ? " and" : "", p->fields[k].name, (unsigned)r->cond[k].lo);
            else
                sb_printf(&sb, "%s %s in %u .. %u", any ? " and" : "", p->fields[k].name,
                          (unsigned)r->cond[k].lo, (unsigned)r->cond[k].hi);
            any = 1;
        }
        sb_puts(&sb, ";");
    }
    str_copy(buf, sb.data ? sb.data : "", (size_t)n);
    sb_free(&sb);
}
