/*
 * pipeline.c -- Compiler driver and JSON report.
 *
 * Runs the phases in order, timing each one with clock():
 *   lex -> parse (+ semantic checks) -> interval partition -> Thompson NFA
 *   -> subset construction -> Hopcroft minimization (by action and by rule)
 *   -> shadow/redundancy analysis on the unminimized DFA -> optimization
 *   -> equivalence of optimized vs original -> DOT export
 * A phase runs only if the previous ones succeeded; errors (including
 * exceeded size limits) become diagnostics, never crashes.  The emitters
 * below write the JSON documents of the CLI; every number the web UI shows
 * comes from here.
 *
 * Complexity: dominated by the subset construction and by the per-rule
 * equivalence checks of analysis and optimization (see those files).
 *
 * Compiler-design concept: the compiler driver / pass manager.
 */
#include "pipeline.h"
#include "dot.h"
#include "oracle.h"
#include "parser_fw.h"
#include "parser_ng.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *PHASE_NAMES[PH_COUNT] = {"lex", "parse", "partition", "nfa", "dfa", "minimize",
                                            "analysis", "optimize", "equivalence", "dot", "total"};

int pipeline_run(Pipeline *pl, const char *src, Syntax syn, MinMode mode, RunLevel level) {
    memset(pl, 0, sizeof *pl);
    pl->syntax = syn;
    pl->min_mode = mode;
    diag_init(&pl->diags);
    tok_log_init(&pl->toks);
    long t_all = clock_now(), t;

    t = clock_now();
    double lex_ms = 0;
    if (syn == SYNTAX_FW) parse_fw(src, &pl->pol, &pl->diags, &pl->toks, &lex_ms);
    else parse_ng(src, &pl->pol, &pl->diags, &pl->toks, &lex_ms);
    pl->ms[PH_LEX] = lex_ms;
    pl->ms[PH_PARSE] = ms_since(t) - lex_ms;
    pl->ok = diag_errors(&pl->diags) == 0;

    if (pl->ok && level >= RUN_AUTOMATA) {
        t = clock_now();
        partition_build(&pl->pt, &pl->pol);
        pl->ms[PH_PARTITION] = ms_since(t);

        char msg[200];
        int needed = 0;
        t = clock_now();
        int rc = nfa_build(&pl->c.nfa, &pl->pol, &pl->pt, &needed);
        pl->ms[PH_NFA] = ms_since(t);
        if (rc != 0) {
            snprintf(msg, sizeof msg, "the Thompson NFA would need %d states (limit %d)", needed, NG_MAX_NFA_STATES);
        } else {
            t = clock_now();
            rc = dfa_build(&pl->c.dfa, &pl->c.nfa, &pl->pol, &pl->pt);
            pl->ms[PH_DFA] = ms_since(t);
            if (rc == -2)
                snprintf(msg, sizeof msg,
                         "the DFA transition table would need more than %ld cells (states x alphabet symbols), "
                         "the memory cap of this server (NETGUARD_MAX_TRANS_CELLS)", dfa_max_trans_cells());
            else if (rc != 0)
                snprintf(msg, sizeof msg, "the subset construction exceeded %d DFA states", NG_MAX_DFA_STATES);
        }
        if (rc != 0) {
            diag_add(&pl->diags, DIAG_ERROR, 1, 1, "limits", "reduce the number or the spread of the rules", "%s", msg);
            pl->ok = 0;
        } else {
            t = clock_now();
            dfa_minimize(&pl->c.min, &pl->c.dfa, MIN_BY_ACTION);
            pl->c.has_min = 1;
            dfa_minimize(&pl->min_rule, &pl->c.dfa, MIN_BY_RULE);
            pl->ms[PH_MINIMIZE] = ms_since(t);
            pl->built = 1;
        }
    }

    if (pl->built && level >= RUN_FULL) {
        t = clock_now();
        int rc = analysis_run(&pl->an, &pl->pol, &pl->pt, &pl->c);
        pl->ms[PH_ANALYSIS] = ms_since(t);
        t = clock_now();
        if (rc == 0) rc = optimize_run(&pl->opt, &pl->pol, syn, &pl->pt, &pl->c, &pl->an);
        pl->ms[PH_OPTIMIZE] = ms_since(t);
        t = clock_now();
        if (rc == 0) rc = equiv_with(&pl->eq, &pl->c.min, &pl->opt.optimized, &pl->pt);
        pl->ms[PH_EQUIV] = ms_since(t);
        if (rc != 0) {
            diag_add(&pl->diags, DIAG_ERROR, 1, 1, "limits", "reduce the number or the spread of the rules",
                     "analysis exceeded the automaton size limits");
            pl->ok = 0;
        } else {
            pl->analysed = 1;
        }
    }
    pl->ms[PH_TOTAL] = ms_since(t_all);
    return pl->ok ? 0 : -1;
}

void pipeline_free(Pipeline *pl) {
    diag_free(&pl->diags);
    tok_log_free(&pl->toks);
    policy_free(&pl->pol);
    partition_free(&pl->pt);
    compiled_free(&pl->c);
    dfa_free(&pl->min_rule);
    analysis_free(&pl->an);
    optimize_free(&pl->opt);
}

/* ------------------------------------------------------------------ */
/* JSON helpers                                                       */

static void emit_packet(Json *j, const Policy *p, const uint32_t *vals) {
    char buf[256];
    json_obj(j);
    json_key(j, "fields");
    json_obj(j);
    for (int k = 0; k < p->nfields; k++) json_ku64(j, p->fields[k].name, vals[k]);
    json_end_obj(j);
    json_key(j, "values");
    json_arr(j);
    for (int k = 0; k < p->nfields; k++) json_u64(j, vals[k]);
    json_end_arr(j);
    fmt_packet(p, vals, buf, sizeof buf);
    json_kstr(j, "text", buf);
    json_end_obj(j);
}

static void emit_ruleset(Json *j, const Policy *p, const RuleSet *s) {
    json_arr(j);
    for (int i = rs_lowest(s); i >= 0; i = rs_next(s, i)) json_str(j, p->rules[i].id);
    json_end_arr(j);
}

static const char *rule_or_default(const Policy *p, int w) { return w >= 0 ? p->rules[w].id : "DEFAULT"; }

static void emit_diags(Json *j, const DiagList *d) {
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

static void emit_policy(Json *j, const Policy *p, Syntax syn) {
    json_obj(j);
    json_kstr(j, "name", p->name);
    json_kstr(j, "syntax", syn == SYNTAX_FW ? "fw" : "ng");
    json_key(j, "fields");
    json_arr(j);
    for (int k = 0; k < p->nfields; k++) {
        json_obj(j);
        json_kstr(j, "name", p->fields[k].name);
        json_ku64(j, "lo", p->fields[k].domain.lo);
        json_ku64(j, "hi", p->fields[k].domain.hi);
        json_kbool(j, "is_ip", field_is_ip(p, k));
        json_end_obj(j);
    }
    json_end_arr(j);
    json_key(j, "actions");
    json_arr(j);
    for (int a = 0; a < p->nactions; a++) json_str(j, p->actions[a]);
    json_end_arr(j);
    json_kstr(j, "default", p->nactions ? p->actions[p->default_action] : "");
    json_key(j, "rules");
    json_arr(j);
    for (int i = 0; i < p->nrules; i++) {
        const Rule *r = &p->rules[i];
        json_obj(j);
        json_kstr(j, "id", r->id);
        json_kint(j, "index", r->index);
        json_kint(j, "line", r->line);
        json_kstr(j, "action", p->actions[r->action]);
        json_kstr(j, "text", r->text);
        json_key(j, "cond");
        json_arr(j);
        for (int k = 0; k < p->nfields; k++) {
            char lo[40], hi[40];
            fmt_value(p, k, r->cond[k].lo, lo, sizeof lo);
            fmt_value(p, k, r->cond[k].hi, hi, sizeof hi);
            json_obj(j);
            json_kstr(j, "field", p->fields[k].name);
            json_ku64(j, "lo", r->cond[k].lo);
            json_ku64(j, "hi", r->cond[k].hi);
            json_kstr(j, "lo_text", lo);
            json_kstr(j, "hi_text", hi);
            json_kbool(j, "any", r->cond[k].lo == p->fields[k].domain.lo && r->cond[k].hi == p->fields[k].domain.hi);
            json_end_obj(j);
        }
        json_end_arr(j);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_end_obj(j);
}

static void emit_partition(Json *j, const Policy *p, const Partition *pt) {
    json_obj(j);
    json_key(j, "fields");
    json_arr(j);
    for (int k = 0; k < pt->nfields; k++) {
        const FieldPart *fp = &pt->f[k];
        json_obj(j);
        json_kstr(j, "name", p->fields[k].name);
        json_kint(j, "offset", fp->offset);
        json_kint(j, "nsyms", fp->nsyms);
        json_key(j, "intervals");
        json_arr(j);
        for (int s = 0; s < fp->nsyms; s++) {
            char lo[40], hi[40];
            fmt_value(p, k, fp->iv[s].lo, lo, sizeof lo);
            fmt_value(p, k, fp->iv[s].hi, hi, sizeof hi);
            json_obj(j);
            json_kint(j, "sym", s);
            json_kint(j, "gsym", fp->offset + s);
            json_ku64(j, "lo", fp->iv[s].lo);
            json_ku64(j, "hi", fp->iv[s].hi);
            json_kstr(j, "lo_text", lo);
            json_kstr(j, "hi_text", hi);
            json_key(j, "rules_covering");
            json_arr(j);
            for (int i = 0; i < p->nrules; i++)
                if (p->rules[i].cond[k].lo <= fp->iv[s].lo && fp->iv[s].hi <= p->rules[i].cond[k].hi)
                    json_str(j, p->rules[i].id);
            json_end_arr(j);
            json_end_obj(j);
        }
        json_end_arr(j);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_ku64(j, "cells", pt->cells);
    json_kint(j, "alphabet", pt->total_syms);
    json_end_obj(j);
}

static void emit_dot(Json *j, char *dot, int too_large) {
    if (dot) json_kstr(j, "dot", dot);
    else json_knull(j, "dot");
    json_kbool(j, "too_large", too_large);
    free(dot);
}

static void emit_min(Json *j, const Pipeline *pl, const DFA *m, MinMode mode) {
    int tl;
    json_obj(j);
    json_kstr(j, "mode", mode == MIN_BY_ACTION ? "action" : "rule");
    json_kint(j, "states", m->nstates);
    json_kint(j, "final_states", dfa_final_count(m));
    emit_dot(j, dot_dfa(m, &pl->pol, &pl->pt, DOT_MAX_NODES, &tl, "M", mode == MIN_BY_RULE), tl);
    json_end_obj(j);
}

static void emit_analysis(Json *j, const Pipeline *pl) {
    const Policy *p = &pl->pol;
    const Analysis *a = &pl->an;
    json_obj(j);
    json_key(j, "rules");
    json_arr(j);
    for (int i = 0; i < p->nrules; i++) {
        const RuleReport *r = &a->r[i];
        json_obj(j);
        json_kstr(j, "id", p->rules[i].id);
        json_kstr(j, "action", p->actions[p->rules[i].action]);
        json_kstr(j, "status", status_name(r->status));
        json_kstr(j, "subtype", r->subtype);
        json_kstr(j, "severity", r->severity);
        json_kbool(j, "conflicting", r->conflicting);
        if (r->status == ST_SHADOWED) {
            json_kstr(j, "shadow_kind", r->union_shadow ? "union" : "single");
            if (r->container >= 0) json_kstr(j, "contained_by", p->rules[r->container].id);
            else json_knull(j, "contained_by");
        }
        json_key(j, "covered_by");
        emit_ruleset(j, p, &r->covered_by);
        json_key(j, "beaten_by");
        emit_ruleset(j, p, &r->beaten_by);
        if (r->status == ST_REDUNDANT) {
            json_key(j, "decided_after_removal_by");
            json_arr(j);
            for (int d = rs_lowest(&r->deciders); d >= 0; d = rs_next(&r->deciders, d)) json_str(j, p->rules[d].id);
            if (r->default_decides) json_str(j, "DEFAULT");
            json_end_arr(j);
        }
        json_kint(j, "win_states", r->win_states);
        json_kint(j, "lose_states", r->lose_states);
        json_key(j, "example");
        if (r->has_example) {
            json_obj(j);
            json_key(j, "packet");
            emit_packet(j, p, r->example);
            json_kstr(j, "decided_by", rule_or_default(p, r->example_winner));
            json_end_obj(j);
        } else {
            json_null(j);
        }
        json_kstr(j, "explanation", r->explanation);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_key(j, "counts");
    json_obj(j);
    for (int s = 0; s < 4; s++) json_kint(j, status_name((RuleStatus)s), a->count[s]);
    json_kint(j, "conflicting", a->conflicting);
    json_kint(j, "high_severity", a->high);
    json_kint(j, "total", p->nrules);
    json_end_obj(j);
    json_end_obj(j);
}

static void emit_optimization(Json *j, const Pipeline *pl) {
    const Policy *p = &pl->pol;
    const Optimization *o = &pl->opt;
    json_obj(j);
    json_kint(j, "original_rules", o->original_rules);
    json_kint(j, "optimized_rules", o->optimized_rules);
    json_key(j, "removed");
    json_arr(j);
    for (int i = 0; i < o->nremoved; i++) {
        json_obj(j);
        json_kstr(j, "id", p->rules[o->removed[i].index].id);
        json_kint(j, "step", i + 1);
        json_kstr(j, "phase", o->removed[i].phase);
        json_kstr(j, "reason", o->removed[i].reason);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_key(j, "kept");
    json_arr(j);
    for (int i = 0; i < p->nrules; i++)
        if (o->keep[i]) json_str(j, p->rules[i].id);
    json_end_arr(j);
    json_kstr(j, "optimized_source", o->source);
    json_end_obj(j);
}

static void emit_equivalence(Json *j, const Pipeline *pl) {
    const Policy *p = &pl->pol;
    json_obj(j);
    json_kbool(j, "equivalent", pl->eq.equivalent);
    json_kint(j, "product_pairs_explored", pl->eq.pairs_explored);
    json_kstr(j, "method", "BFS over the product of the two action-minimized DFAs, on the original partition");
    json_key(j, "counterexample");
    if (pl->eq.has_counterexample) {
        int wo, wn;
        int ao = oracle_eval(p, pl->eq.packet, &wo);
        int an = oracle_eval(&pl->opt.optimized, pl->eq.packet, &wn);
        json_obj(j);
        json_key(j, "packet");
        emit_packet(j, p, pl->eq.packet);
        json_kstr(j, "original_action", p->actions[pl->eq.action_a]);
        json_kstr(j, "optimized_action", p->actions[pl->eq.action_b]);
        json_kstr(j, "oracle_original", p->actions[ao]);
        json_kstr(j, "oracle_optimized", p->actions[an]);
        json_end_obj(j);
    } else {
        json_null(j);
    }
    json_end_obj(j);
}

void emit_compile_json(Json *j, Pipeline *pl) {
    const Policy *p = &pl->pol;
    long t = clock_now();
    int tl;
    json_obj(j);
    json_kbool(j, "ok", pl->ok);
    json_key(j, "diagnostics");
    emit_diags(j, &pl->diags);
    json_key(j, "tokens");
    json_arr(j);
    for (int i = 0; i < pl->toks.n; i++) {
        json_obj(j);
        json_kint(j, "line", pl->toks.v[i].line);
        json_kint(j, "col", pl->toks.v[i].col);
        json_kstr(j, "type", pl->toks.v[i].type);
        json_kstr(j, "lexeme", pl->toks.v[i].lexeme);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_key(j, "policy");
    emit_policy(j, p, pl->syntax);

    if (pl->built) {
        json_key(j, "partition");
        emit_partition(j, p, &pl->pt);
        json_key(j, "nfa");
        json_obj(j);
        json_kint(j, "states", pl->c.nfa.nstates);
        json_kint(j, "eps_edges", pl->c.nfa.eps_edges);
        json_kint(j, "sym_edges", pl->c.nfa.sym_edges);
        emit_dot(j, dot_nfa(&pl->c.nfa, p, &pl->pt, DOT_MAX_NODES, &tl), tl);
        json_end_obj(j);
        json_key(j, "dfa");
        json_obj(j);
        json_kint(j, "states", pl->c.dfa.nstates);
        json_kint(j, "final_states", dfa_final_count(&pl->c.dfa));
        json_kint(j, "alphabet", pl->c.dfa.nsyms);
        json_kbool(j, "complete", 1);
        json_kbool(j, "has_sink", pl->c.dfa.sink >= 0);
        emit_dot(j, dot_dfa(&pl->c.dfa, p, &pl->pt, DOT_MAX_NODES, &tl, "D", 1), tl);
        json_end_obj(j);
        json_key(j, "min_dfa");
        emit_min(j, pl, pl->min_mode == MIN_BY_ACTION ? &pl->c.min : &pl->min_rule, pl->min_mode);
        json_key(j, "min_dfa_modes");
        json_obj(j);
        json_key(j, "action");
        emit_min(j, pl, &pl->c.min, MIN_BY_ACTION);
        json_key(j, "rule");
        emit_min(j, pl, &pl->min_rule, MIN_BY_RULE);
        json_end_obj(j);
    } else {
        json_knull(j, "partition");
        json_knull(j, "nfa");
        json_knull(j, "dfa");
        json_knull(j, "min_dfa");
        json_knull(j, "min_dfa_modes");
    }
    pl->ms[PH_DOT] = ms_since(t);
    pl->ms[PH_TOTAL] += pl->ms[PH_DOT];
    if (pl->analysed) {
        json_key(j, "analysis");
        emit_analysis(j, pl);
        json_key(j, "optimization");
        emit_optimization(j, pl);
        json_key(j, "equivalence");
        emit_equivalence(j, pl);
    } else {
        json_knull(j, "analysis");
        json_knull(j, "optimization");
        json_knull(j, "equivalence");
    }
    json_key(j, "stats");
    json_obj(j);
    json_key(j, "phase_ms");
    json_obj(j);
    for (int i = 0; i < PH_COUNT; i++) json_knum(j, PHASE_NAMES[i], pl->ms[i]);
    json_end_obj(j);
    json_key(j, "limits");
    json_obj(j);
    json_kint(j, "rules", NG_MAX_RULES);
    json_kint(j, "nfa_states", NG_MAX_NFA_STATES);
    json_kint(j, "dfa_states", NG_MAX_DFA_STATES);
    json_end_obj(j);
    json_end_obj(j);
    json_end_obj(j);
}

void emit_error_json(Json *j, const char *msg) {
    json_obj(j);
    json_kbool(j, "ok", 0);
    json_kstr(j, "error", msg);
    json_end_obj(j);
}

void emit_classify_json(Json *j, const Pipeline *pl, const uint32_t *vals, const char *text) {
    const Policy *p = &pl->pol;
    Classification c;
    classify_packet(&c, p, &pl->pt, &pl->c.min, &pl->c.dfa, vals);
    char buf[300], v[40], r[96];
    json_obj(j);
    json_kbool(j, "ok", 1);
    json_kstr(j, "input", text);
    json_key(j, "packet");
    emit_packet(j, p, vals);
    json_kstr(j, "decision", p->actions[c.decision]);
    json_kstr(j, "decided_by", rule_or_default(p, c.winner));
    if (c.winner >= 0) {
        json_kstr(j, "winner", p->rules[c.winner].id);
        json_kstr(j, "winner_text", p->rules[c.winner].text);
    } else {
        json_knull(j, "winner");
        json_knull(j, "winner_text");
    }
    json_kint(j, "winner_index", c.winner);
    json_key(j, "matched");
    emit_ruleset(j, p, &c.matched);
    json_key(j, "other_matched");
    json_arr(j);
    for (int i = rs_lowest(&c.matched); i >= 0; i = rs_next(&c.matched, i))
        if (i != c.winner) json_str(j, p->rules[i].id);
    json_end_arr(j);
    json_key(j, "failures");
    json_arr(j);
    for (int f = 0; f < c.nfails; f++) {
        const Rule *ru = &p->rules[c.fails[f].rule];
        int k = c.fails[f].field;
        fmt_value(p, k, vals[k], v, sizeof v);
        fmt_range(p, k, ru->cond[k], r, sizeof r);
        snprintf(buf, sizeof buf, "%s: %s %s \xE2\x88\x89 %s", ru->id, p->fields[k].name, v, r);
        json_obj(j);
        json_kstr(j, "rule", ru->id);
        json_kstr(j, "field", p->fields[k].name);
        json_kstr(j, "value", v);
        json_kstr(j, "range", r);
        json_kstr(j, "text", buf);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_key(j, "trace");
    json_arr(j);
    for (int k = 0; k < p->nfields; k++) {
        const TraceStep *t = &c.trace[k];
        Range ir = {t->iv.lo, t->iv.hi};
        fmt_value(p, k, t->value, v, sizeof v);
        fmt_range(p, k, ir, r, sizeof r);
        json_obj(j);
        json_kstr(j, "field", p->fields[k].name);
        json_ku64(j, "value", t->value);
        json_kstr(j, "value_text", v);
        json_kint(j, "sym", t->sym);
        json_kint(j, "gsym", t->gsym);
        json_kstr(j, "interval", r);
        json_kint(j, "from", t->from);
        json_kint(j, "to", t->to);
        json_kint(j, "dfa_from", t->dfa_from);
        json_kint(j, "dfa_to", t->dfa_to);
        json_end_obj(j);
    }
    json_end_arr(j);
    json_kint(j, "min_final_state", c.min_final);
    json_kint(j, "dfa_final_state", c.dfa_final);
    json_key(j, "oracle");
    json_obj(j);
    json_kstr(j, "decision", p->actions[c.oracle_decision]);
    json_kstr(j, "decided_by", rule_or_default(p, c.oracle_winner));
    json_end_obj(j);
    json_kbool(j, "oracle_agrees", c.oracle_decision == c.decision && c.oracle_winner == c.winner);
    json_end_obj(j);
}

/* Random value of field k, biased toward rule boundaries +-1. */
static uint32_t random_value(Rng *rng, const Policy *p, int k) {
    Range dom = p->fields[k].domain;
    if (p->nrules == 0 || rng_next(rng) % 4 == 0) return (uint32_t)rng_range(rng, dom.lo, dom.hi);
    const Rule *r = &p->rules[rng_next(rng) % (uint64_t)p->nrules];
    int64_t v = (rng_next(rng) & 1) ? (int64_t)r->cond[k].lo : (int64_t)r->cond[k].hi;
    v += (int64_t)(rng_next(rng) % 3) - 1;
    if (v < (int64_t)dom.lo) v = dom.lo;
    if (v > (int64_t)dom.hi) v = dom.hi;
    return (uint32_t)v;
}

void emit_verify_json(Json *j, const Pipeline *pl, long n, uint64_t seed) {
    const Policy *p = &pl->pol;
    Rng rng = {seed};
    long agree_min = 0, agree_dfa = 0, agree_opt = 0, agree_optdfa = 0;
    uint32_t vals[NG_MAX_FIELDS];
    Compiled opt;
    char msg[160];
    int have_opt = compile_policy(&opt, &pl->opt.optimized, &pl->pt, 1, msg, sizeof msg) == 0;
    json_obj(j);
    json_kbool(j, "ok", 1);
    json_kint(j, "n", n);
    json_ku64(j, "seed", seed);
    json_key(j, "mismatches");
    json_arr(j);
    int shown = 0;
    for (long i = 0; i < n; i++) {
        for (int k = 0; k < p->nfields; k++) vals[k] = random_value(&rng, p, k);
        int ow;
        int o = oracle_eval(p, vals, &ow);
        int m = pl->c.min.output[dfa_run(&pl->c.min, &pl->pt, vals, NULL)];
        int ds = dfa_run(&pl->c.dfa, &pl->pt, vals, NULL);
        int oo = oracle_eval(&pl->opt.optimized, vals, NULL);
        int od = have_opt ? opt.min.output[dfa_run(&opt.min, &pl->pt, vals, NULL)] : -1;
        int ok_min = m == o, ok_dfa = pl->c.dfa.output[ds] == o && pl->c.dfa.winner[ds] == ow;
        int ok_opt = oo == o, ok_od = od == o;
        agree_min += ok_min;
        agree_dfa += ok_dfa;
        agree_opt += ok_opt;
        agree_optdfa += ok_od;
        if ((!ok_min || !ok_dfa || !ok_opt || !ok_od) && shown < 10) {
            shown++;
            json_obj(j);
            json_key(j, "packet");
            emit_packet(j, p, vals);
            json_kstr(j, "oracle", p->actions[o]);
            json_kstr(j, "min_dfa", p->actions[m]);
            json_kstr(j, "optimized_oracle", p->actions[oo]);
            json_end_obj(j);
        }
    }
    json_end_arr(j);
    json_key(j, "min_dfa_vs_oracle");
    json_obj(j); json_kint(j, "agree", agree_min); json_kint(j, "disagree", n - agree_min); json_end_obj(j);
    json_key(j, "dfa_vs_oracle");
    json_obj(j); json_kint(j, "agree", agree_dfa); json_kint(j, "disagree", n - agree_dfa); json_end_obj(j);
    json_key(j, "optimized_vs_original");
    json_obj(j); json_kint(j, "agree", agree_opt); json_kint(j, "disagree", n - agree_opt); json_end_obj(j);
    json_key(j, "optimized_min_dfa_vs_original");
    json_obj(j); json_kint(j, "agree", agree_optdfa); json_kint(j, "disagree", n - agree_optdfa); json_end_obj(j);
    json_kbool(j, "all_agree", agree_min == n && agree_dfa == n && agree_opt == n && agree_optdfa == n);
    json_kint(j, "original_rules", p->nrules);
    json_kint(j, "optimized_rules", pl->opt.optimized.nrules);
    json_end_obj(j);
    compiled_free(&opt);
}
