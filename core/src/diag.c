/*
 * diag.c -- Diagnostic collection.
 *
 * A growable vector of diagnostics.  Collecting instead of aborting is what
 * makes panic-mode error recovery useful: the lexer, both parsers and the
 * semantic checker all append here and the driver reports everything at the
 * end.  diag_sort is an insertion sort (stable, O(d^2), d is tiny).
 */
#include "diag.h"
#include "util.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void diag_init(DiagList *d) { d->items = NULL; d->count = d->cap = 0; }

void diag_free(DiagList *d) { free(d->items); diag_init(d); }

void diag_add(DiagList *d, DiagLevel lvl, int line, int col, const char *phase,
              const char *hint, const char *fmt, ...) {
    if (d->count == d->cap) {
        d->cap = d->cap ? d->cap * 2 : 16;
        d->items = xrealloc(d->items, sizeof(Diag) * (size_t)d->cap);
    }
    Diag *g = &d->items[d->count++];
    g->level = lvl;
    g->line = line;
    g->col = col;
    str_copy(g->phase, phase, sizeof g->phase);
    str_copy(g->hint, hint ? hint : "", sizeof g->hint);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g->message, sizeof g->message, fmt, ap);
    va_end(ap);
}

int diag_errors(const DiagList *d) {
    int n = 0;
    for (int i = 0; i < d->count; i++)
        if (d->items[i].level == DIAG_ERROR) n++;
    return n;
}

void diag_sort(DiagList *d) {
    for (int i = 1; i < d->count; i++) {
        Diag key = d->items[i];
        int j = i - 1;
        while (j >= 0 && (d->items[j].line > key.line ||
                          (d->items[j].line == key.line && d->items[j].col > key.col))) {
            d->items[j + 1] = d->items[j];
            j--;
        }
        d->items[j + 1] = key;
    }
}
