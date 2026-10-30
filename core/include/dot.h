/*
 * dot.h -- Graphviz DOT export of the NFA, DFA and minimized DFA.
 */
#ifndef NG_DOT_H
#define NG_DOT_H

#include "dfa.h"
#include "ir.h"
#include "nfa.h"
#include "partition.h"

#define DOT_MAX_NODES 200

/* Return a heap DOT string, or NULL with *too_large = 1 when the graph has
 * more than limit nodes (limit <= 0: no limit). */
char *dot_nfa(const NFA *n, const Policy *p, const Partition *pt, int limit, int *too_large);
/* prefix names the states ("D" / "M"); show_winner adds the winning rule. */
char *dot_dfa(const DFA *d, const Policy *p, const Partition *pt, int limit, int *too_large,
              const char *prefix, int show_winner);

#endif
