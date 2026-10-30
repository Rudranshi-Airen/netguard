/*
 * dot.c -- Graphviz DOT export of the automata.
 *
 * Algorithm.  Nodes are emitted in state order.  Edges are grouped by
 * (source, target): all symbols leading from s to the same t are merged
 * into ONE edge whose label lists maximal runs of consecutive intervals,
 * e.g. "dst_port 80–442, 444–8080" (runs of adjacent symbols coalesce
 * because adjacent intervals are contiguous ranges of values).  A run that
 * covers the whole domain prints as "field *".  Final states are double
 * circles labelled with their action (and, for the unminimized DFA or the
 * rule-minimized DFA, the winning rule).  The SINK state is omitted: every
 * missing symbol goes there by construction, and drawing it would add an
 * edge from every state.  Graphs with more than `limit` nodes are not
 * rendered; the caller reports too_large instead.
 *
 * Complexity: O(states * symbols-per-state) plus label building, linear in
 * the size of the output.
 *
 * Compiler-design concept: dumping the compiler's intermediate
 * representations (like flex -T or a compiler's -fdump-* options) so the
 * phases can be inspected visually.
 */
#include "dot.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *PALETTE[] = {"#dbeafe", "#fef3c7", "#ede9fe", "#cffafe", "#fce7f3", "#e0e7ff", "#ecfccb", "#ffedd5"};

static const char *action_color(const Policy *p, int a) {
    if (str_ieq(p->actions[a], "ALLOW")) return "#bbf7d0";
    if (str_ieq(p->actions[a], "DENY")) return "#fecaca";
    return PALETTE[a % 8];
}

static void short_value(const Policy *p, int k, uint32_t v, char *buf, size_t n) {
    if (field_is_ip(p, k)) ip_to_str(v, buf, n);
    else if (str_ieq(p->fields[k].name, "proto") && (v == 1 || v == 6 || v == 17))
        str_copy(buf, v == 1 ? "ICMP" : v == 6 ? "TCP" : "UDP", n);
    else snprintf(buf, n, "%u", (unsigned)v);
}

/* Label for the local symbols js[0..m) (ascending) of field k. */
static void run_label(StrBuf *sb, const Policy *p, const Partition *pt, int k, const int *js, int m) {
    const FieldPart *fp = &pt->f[k];
    if (m == fp->nsyms) { sb_printf(sb, "%s *", p->fields[k].name); return; }
    sb_printf(sb, "%s ", p->fields[k].name);
    int runs = 0;
    for (int i = 0; i < m;) {
        int j = i;
        while (j + 1 < m && js[j + 1] == js[j] + 1) j++;
        if (runs == 5) {
            int rest = 0;
            for (int x = i; x < m;) {
                int y = x;
                while (y + 1 < m && js[y + 1] == js[y] + 1) y++;
                rest++;
                x = y + 1;
            }
            sb_printf(sb, ", +%d more", rest);
            return;
        }
        char a[24], b[24];
        short_value(p, k, fp->iv[js[i]].lo, a, sizeof a);
        short_value(p, k, fp->iv[js[j]].hi, b, sizeof b);
        if (fp->iv[js[i]].lo == fp->iv[js[j]].hi) sb_printf(sb, "%s%s", runs ? ", " : "", a);
        else sb_printf(sb, "%s%s\xE2\x80\x93%s", runs ? ", " : "", a, b);   /* en dash */
        runs++;
        i = j + 1;
    }
}

char *dot_nfa(const NFA *n, const Policy *p, const Partition *pt, int limit, int *too_large) {
    *too_large = limit > 0 && n->nstates > limit;
    if (*too_large) return NULL;
    StrBuf sb;
    sb_init(&sb);
    sb_puts(&sb, "digraph NFA {\n  rankdir=LR; bgcolor=\"transparent\";\n"
                 "  node [shape=circle, fontname=\"Helvetica\", fontsize=10, style=filled, fillcolor=\"#f8fafc\"];\n"
                 "  edge [fontname=\"Helvetica\", fontsize=9];\n  __start [shape=point, width=0.08];\n");
    sb_printf(&sb, "  __start -> n%d;\n", n->start);
    for (int s = 0; s < n->nstates; s++) {
        if (n->accept[s] >= 0) {
            const Rule *r = &p->rules[n->accept[s]];
            sb_printf(&sb, "  n%d [shape=doublecircle, label=\"%s\\n%s\", fillcolor=\"%s\"];\n", s, r->id,
                      p->actions[r->action], action_color(p, r->action));
        } else {
            sb_printf(&sb, "  n%d [label=\"%d\"];\n", s, s);
        }
    }
    int *js = xmalloc(sizeof(int) * (size_t)(pt->total_syms + 1));
    for (int s = 0; s < n->nstates; s++) {
        int e0 = n->edge_start[s], e1 = n->edge_start[s + 1];
        for (int e = e0; e < e1; e++) {
            int t = n->edges[e].to, dup = 0;
            for (int x = e0; x < e && !dup; x++) dup = n->edges[x].to == t;
            if (dup) continue;
            /* epsilon edge(s) to t */
            int has_eps = 0, m = 0, field = -1;
            for (int x = e; x < e1; x++) {
                if (n->edges[x].to != t) continue;
                if (n->edges[x].sym == NFA_EPS) has_eps = 1;
                else {
                    field = pt->sym_field[n->edges[x].sym];
                    js[m++] = pt->sym_local[n->edges[x].sym];
                }
            }
            if (has_eps) sb_printf(&sb, "  n%d -> n%d [label=\"\xCE\xB5\", style=dashed, color=\"#94a3b8\"];\n", s, t);
            if (m > 0) {
                sb_printf(&sb, "  n%d -> n%d [label=\"", s, t);
                run_label(&sb, p, pt, field, js, m);
                sb_puts(&sb, "\"];\n");
            }
        }
    }
    free(js);
    sb_puts(&sb, "}\n");
    return sb_take(&sb);
}

char *dot_dfa(const DFA *d, const Policy *p, const Partition *pt, int limit, int *too_large,
              const char *prefix, int show_winner) {
    int visible = d->nstates - (d->sink >= 0 ? 1 : 0);
    *too_large = limit > 0 && visible > limit;
    if (*too_large) return NULL;
    StrBuf sb;
    sb_init(&sb);
    sb_printf(&sb, "digraph %s {\n  rankdir=LR; bgcolor=\"transparent\";\n", prefix[0] == 'M' ? "MinDFA" : "DFA");
    sb_puts(&sb, "  label=\"SINK state (wrong-layer symbols) omitted\"; labelloc=b; fontsize=9; fontname=\"Helvetica\";\n"
                 "  node [shape=circle, fontname=\"Helvetica\", fontsize=10, style=filled, fillcolor=\"#f8fafc\"];\n"
                 "  edge [fontname=\"Helvetica\", fontsize=9];\n  __start [shape=point, width=0.08];\n");
    sb_printf(&sb, "  __start -> %s%d;\n", prefix, d->start);
    for (int s = 0; s < d->nstates; s++) {
        if (s == d->sink) continue;
        if (d->layer[s] == d->nfields) {
            int a = d->output[s];
            sb_printf(&sb, "  %s%d [shape=doublecircle, fillcolor=\"%s\", label=\"%s%d\\n%s", prefix, s,
                      action_color(p, a), prefix, s, p->actions[a]);
            if (show_winner && d->winner[s] >= 0) sb_printf(&sb, "\\nwin %s", p->rules[d->winner[s]].id);
            else if (show_winner && d->winner[s] == -1) sb_puts(&sb, "\\nDEFAULT");
            sb_puts(&sb, "\"];\n");
        } else {
            sb_printf(&sb, "  %s%d [label=\"%s%d\"];\n", prefix, s, prefix, s);
        }
    }
    int maxsyms = 1;
    for (int k = 0; k < pt->nfields; k++)
        if (pt->f[k].nsyms > maxsyms) maxsyms = pt->f[k].nsyms;
    int *tgt = xmalloc(sizeof(int) * (size_t)maxsyms);
    int *js = xmalloc(sizeof(int) * (size_t)maxsyms);
    for (int s = 0; s < d->nstates; s++) {
        int L = d->layer[s];
        if (s == d->sink || L < 0 || L >= d->nfields) continue;
        const FieldPart *fp = &pt->f[L];
        for (int j = 0; j < fp->nsyms; j++) tgt[j] = d->trans[(size_t)s * d->nsyms + fp->offset + j];
        for (int j = 0; j < fp->nsyms; j++) {
            int t = tgt[j], first = 1;
            for (int x = 0; x < j; x++)
                if (tgt[x] == t) { first = 0; break; }
            if (!first || t == d->sink) continue;
            int m = 0;
            for (int x = j; x < fp->nsyms; x++)
                if (tgt[x] == t) js[m++] = x;
            sb_printf(&sb, "  %s%d -> %s%d [label=\"", prefix, s, prefix, t);
            run_label(&sb, p, pt, L, js, m);
            sb_puts(&sb, "\"];\n");
        }
    }
    free(tgt);
    free(js);
    sb_puts(&sb, "}\n");
    return sb_take(&sb);
}
