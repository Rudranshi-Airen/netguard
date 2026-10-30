/*
 * sema.h -- Semantic analysis of parsed .fw statements.
 *
 * The parser builds RawRule / RawDefault records (a tiny AST that still
 * holds the tokens, so diagnostics can point at exact columns); sema checks
 * them and lowers them to the IR (Rule with one Range per field).
 */
#ifndef NG_SEMA_H
#define NG_SEMA_H

#include "diag.h"
#include "ir.h"
#include "lexer.h"

typedef enum { ADDR_ANY, ADDR_IP, ADDR_CIDR, ADDR_RANGE } AddrKind;
typedef struct { AddrKind kind; Token a, b; } RawAddr;

typedef enum { PORT_OMITTED, PORT_ANY, PORT_SINGLE, PORT_RANGE } PortKind;

typedef struct {
    int      line;
    Token    action, proto;
    RawAddr  src, dst;
    PortKind port_kind;
    Token    port_kw, p1, p2;
} RawRule;

typedef struct { Token kw, action; } RawDefault;

/* Field layout of the firewall packet model. */
enum { FW_PROTO = 0, FW_SRC_IP = 1, FW_DST_IP = 2, FW_DST_PORT = 3, FW_NFIELDS = 4 };

/* Initialise an empty firewall policy (fields, actions ALLOW/DENY). */
void sema_fw_init_policy(Policy *p);
/* Check one rule and lower it into *out.  Returns 0 if it is valid. */
int  sema_fw_rule(const Policy *p, const RawRule *rr, Rule *out, DiagList *d);
/* Check the DEFAULT declarations (at most one) and set default_action. */
void sema_fw_defaults(Policy *p, const RawDefault *defs, int ndefs, DiagList *d);

#endif
