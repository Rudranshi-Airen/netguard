/*
 * ir.h -- Shared intermediate representation (IR) of a rule policy.
 *
 * Both front ends (the .fw firewall parser and the .ng generic parser)
 * lower their input to this IR; every back-end phase (partitioning,
 * Thompson NFA, subset construction, minimization, analysis, optimization,
 * equivalence, classification) consumes only this IR.  This is the classic
 * front-end / back-end split of a compiler around a common IR.
 *
 * A packet is a fixed-order vector of nfields unsigned integers.  Each rule
 * constrains every field to an inclusive Range (a field the rule does not
 * mention is constrained to the whole domain).  Rule priority is the rule's
 * index: the lowest index that matches wins (first match wins).
 */
#ifndef NG_IR_H
#define NG_IR_H

#include <stdint.h>

#define NG_MAX_FIELDS  8
#define NG_MAX_ACTIONS 16
#define NG_NAME_LEN    32

/* Resource limits: exceeding one produces a diagnostic, never a crash. */
#define NG_MAX_RULES       2048
#define NG_MAX_NFA_STATES  400000
#define NG_MAX_DFA_STATES  200000

typedef struct { uint32_t lo, hi; } Range;              /* inclusive; use uint64_t for hi+1 math */

typedef struct { char name[NG_NAME_LEN]; Range domain; } FieldDecl;

typedef struct {
    int   index;                 /* 0-based priority (0 = highest) */
    char  id[NG_NAME_LEN];       /* "R1" or "t1" */
    int   line;
    int   action;                /* index into Policy.actions */
    Range cond[NG_MAX_FIELDS];   /* unconstrained field = full domain */
    char  text[256];             /* original source text for display */
} Rule;

typedef struct {
    char      name[64];
    int       nfields;
    FieldDecl fields[NG_MAX_FIELDS];
    int       nactions;
    char      actions[NG_MAX_ACTIONS][NG_NAME_LEN];
    int       default_action;
    int       nrules;
    Rule     *rules;             /* heap array */
} Policy;

/* Syntax of the source a policy came from (decides how it is printed back). */
typedef enum { SYNTAX_FW = 0, SYNTAX_NG = 1 } Syntax;

void policy_init(Policy *p);
void policy_free(Policy *p);
/* Append a rule (copied); index is assigned automatically. */
void policy_add_rule(Policy *p, const Rule *r);
/* Intern an action name; returns its index or -1 when NG_MAX_ACTIONS is hit. */
int  policy_intern_action(Policy *p, const char *name);
/* dst := src restricted to rules with keep[i] != 0; indices are renumbered,
 * ids are preserved.  dst must be uninitialised or freed. */
void policy_subset(Policy *dst, const Policy *src, const unsigned char *keep);
/* dst := deep copy of src. */
void policy_copy(Policy *dst, const Policy *src);
/* 1 if value v satisfies rule r on field k. */
int  rule_field_contains(const Rule *r, int k, uint32_t v);

/* Printing helpers.  Field values of fields named "*ip" print as dotted
 * IPv4; the "proto" field prints with its protocol name. */
int  field_is_ip(const Policy *p, int k);
void fmt_value(const Policy *p, int k, uint32_t v, char *buf, int n);
void fmt_range(const Policy *p, int k, Range r, char *buf, int n);
/* Render a packet as "proto=6 src_ip=10.0.0.0 ..." */
void fmt_packet(const Policy *p, const uint32_t *vals, char *buf, int n);
/* Pretty-print one rule back to source syntax (canonical form). */
void fmt_rule_source(const Policy *p, Syntax syn, const Rule *r, char *buf, int n);

#endif
