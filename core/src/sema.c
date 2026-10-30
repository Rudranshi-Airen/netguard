/*
 * sema.c -- Semantic checks and lowering of .fw rules to the IR.
 *
 * Algorithm.  One pass over each parsed rule (an attribute-evaluation pass
 * over the tiny AST built by the parser):
 *   - protocol name / number  -> Range on field proto   (TCP=6 UDP=17 ICMP=1 ANY=0..255)
 *   - ANY / IPv4 / CIDR / a-b -> Range on src_ip, dst_ip
 *       octet > 255             error
 *       CIDR prefix > 32        error
 *       CIDR with host bits set warning, normalised to the network address
 *       range lo > hi           error
 *   - PORT spec               -> Range on dst_port (omitted = ANY)
 *       port > 65535            error
 *       range lo > hi           error
 *       PORT with ICMP          warning, port ignored (treated as ANY)
 *   - DEFAULT declarations: at most one (duplicate DEFAULT is an error).
 * Every check reports and continues, so all semantic errors are collected.
 *
 * Complexity: O(1) per rule, O(R) for the policy.
 *
 * Compiler-design concept: semantic analysis (static checks that a
 * context-free grammar cannot express) and lowering of the AST to an IR.
 */
#include "sema.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

void sema_fw_init_policy(Policy *p) {
    policy_init(p);
    str_copy(p->name, "firewall", sizeof p->name);
    p->nfields = FW_NFIELDS;
    str_copy(p->fields[FW_PROTO].name, "proto", NG_NAME_LEN);
    p->fields[FW_PROTO].domain = (Range){0, 255};
    str_copy(p->fields[FW_SRC_IP].name, "src_ip", NG_NAME_LEN);
    p->fields[FW_SRC_IP].domain = (Range){0, 0xFFFFFFFFu};
    str_copy(p->fields[FW_DST_IP].name, "dst_ip", NG_NAME_LEN);
    p->fields[FW_DST_IP].domain = (Range){0, 0xFFFFFFFFu};
    str_copy(p->fields[FW_DST_PORT].name, "dst_port", NG_NAME_LEN);
    p->fields[FW_DST_PORT].domain = (Range){0, 65535};
    policy_intern_action(p, "ALLOW");
    policy_intern_action(p, "DENY");
    p->default_action = 1;                    /* DENY when no DEFAULT is given */
}

/* Validate the octets of an IPV4/CIDR token and assemble the address. */
static int ip_value(const Token *t, uint32_t *ip, DiagList *d) {
    int ok = 1;
    uint32_t v = 0;
    for (int i = 0; i < 4; i++) {
        if (t->oct[i] > 255) {
            diag_add(d, DIAG_ERROR, t->line, t->col, "semantic",
                     "each IPv4 octet must be between 0 and 255",
                     "octet %u in '%s' is greater than 255", (unsigned)t->oct[i], t->lexeme);
            ok = 0;
        }
        v = (v << 8) | (t->oct[i] & 255u);
    }
    *ip = v;
    return ok;
}

static int addr_range(const RawAddr *a, Range *out, DiagList *d) {
    uint32_t ip = 0, ip2 = 0;
    switch (a->kind) {
    case ADDR_ANY:
        *out = (Range){0, 0xFFFFFFFFu};
        return 1;
    case ADDR_IP:
        if (!ip_value(&a->a, &ip, d)) return 0;
        *out = (Range){ip, ip};
        return 1;
    case ADDR_CIDR: {
        int ok = ip_value(&a->a, &ip, d);
        if (a->a.prefix > 32) {
            diag_add(d, DIAG_ERROR, a->a.line, a->a.col, "semantic",
                     "an IPv4 prefix length must be between 0 and 32",
                     "CIDR prefix /%u in '%s' is greater than 32", (unsigned)a->a.prefix, a->a.lexeme);
            return 0;
        }
        if (!ok) return 0;
        uint32_t mask = a->a.prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - a->a.prefix);
        if ((ip & ~mask) != 0) {
            char net[16];
            ip_to_str(ip & mask, net, sizeof net);
            diag_add(d, DIAG_WARNING, a->a.line, a->a.col, "semantic",
                     "the host bits were cleared; write the network address to silence this",
                     "CIDR '%s' has host bits set; normalized to %s/%u", a->a.lexeme, net,
                     (unsigned)a->a.prefix);
        }
        *out = (Range){ip & mask, (ip & mask) | ~mask};
        return 1;
    }
    case ADDR_RANGE: {
        int ok = ip_value(&a->a, &ip, d);
        ok = ip_value(&a->b, &ip2, d) && ok;
        if (!ok) return 0;
        if (ip > ip2) {
            diag_add(d, DIAG_ERROR, a->a.line, a->a.col, "semantic",
                     "write the lower address first",
                     "address range %s-%s is empty (low end > high end)", a->a.lexeme, a->b.lexeme);
            return 0;
        }
        *out = (Range){ip, ip2};
        return 1;
    }
    }
    return 0;
}

static int port_value(const Token *t, uint32_t *v, DiagList *d) {
    if (t->ival > 65535) {
        diag_add(d, DIAG_ERROR, t->line, t->col, "semantic", "ports are 0..65535",
                 "port %s is out of range 0..65535", t->lexeme);
        return 0;
    }
    *v = (uint32_t)t->ival;
    return 1;
}

int sema_fw_rule(const Policy *p, const RawRule *rr, Rule *out, DiagList *d) {
    int ok = 1;
    memset(out, 0, sizeof *out);
    out->line = rr->line;
    out->action = str_ieq(rr->action.lexeme, "ALLOW") ? 0 : 1;
    for (int k = 0; k < p->nfields; k++) out->cond[k] = p->fields[k].domain;

    /* protocol */
    const Token *pt = &rr->proto;
    if (pt->type == TOK_ANY) out->cond[FW_PROTO] = (Range){0, 255};
    else if (pt->type == TOK_INT) {
        if (pt->ival > 255) {
            diag_add(d, DIAG_ERROR, pt->line, pt->col, "semantic",
                     "IP protocol numbers are 0..255 (TCP=6, UDP=17, ICMP=1)",
                     "protocol number %s is out of range", pt->lexeme);
            ok = 0;
        } else {
            out->cond[FW_PROTO] = (Range){(uint32_t)pt->ival, (uint32_t)pt->ival};
        }
    } else {
        uint32_t v = str_ieq(pt->lexeme, "TCP") ? 6u : str_ieq(pt->lexeme, "UDP") ? 17u : 1u;
        out->cond[FW_PROTO] = (Range){v, v};
    }
    int is_icmp = ok && out->cond[FW_PROTO].lo == 1 && out->cond[FW_PROTO].hi == 1;

    /* addresses (evaluate both so all errors are reported) */
    int ok_src = addr_range(&rr->src, &out->cond[FW_SRC_IP], d);
    int ok_dst = addr_range(&rr->dst, &out->cond[FW_DST_IP], d);
    ok = ok && ok_src && ok_dst;

    /* port */
    if (rr->port_kind == PORT_SINGLE || rr->port_kind == PORT_RANGE) {
        uint32_t lo = 0, hi = 0;
        int pok = port_value(&rr->p1, &lo, d);
        if (rr->port_kind == PORT_RANGE) pok = port_value(&rr->p2, &hi, d) && pok;
        else hi = lo;
        if (pok && lo > hi) {
            diag_add(d, DIAG_ERROR, rr->p1.line, rr->p1.col, "semantic", "write the lower port first",
                     "port range %u-%u is empty (low end > high end)", (unsigned)lo, (unsigned)hi);
            pok = 0;
        }
        if (pok) out->cond[FW_DST_PORT] = (Range){lo, hi};
        ok = ok && pok;
    }
    if (is_icmp && rr->port_kind != PORT_OMITTED) {
        diag_add(d, DIAG_WARNING, rr->port_kw.line, rr->port_kw.col, "semantic",
                 "ICMP has no ports; remove the PORT clause",
                 "PORT given with ICMP is ignored (treated as ANY)");
        out->cond[FW_DST_PORT] = p->fields[FW_DST_PORT].domain;
    }
    return ok ? 0 : -1;
}

void sema_fw_defaults(Policy *p, const RawDefault *defs, int ndefs, DiagList *d) {
    for (int i = 0; i < ndefs; i++) {
        if (i == 0) {
            p->default_action = str_ieq(defs[i].action.lexeme, "ALLOW") ? 0 : 1;
        } else {
            diag_add(d, DIAG_ERROR, defs[i].kw.line, defs[i].kw.col, "semantic",
                     "keep a single DEFAULT line",
                     "duplicate DEFAULT (first declared on line %d)", defs[0].kw.line);
        }
    }
}
