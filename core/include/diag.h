/*
 * diag.h -- Diagnostics (errors / warnings) with source positions and hints.
 *
 * Every phase appends to one DiagList instead of aborting, so the user sees
 * all problems in one run (as GCC / Clang do).
 */
#ifndef NG_DIAG_H
#define NG_DIAG_H

typedef enum { DIAG_ERROR = 0, DIAG_WARNING = 1 } DiagLevel;

typedef struct {
    DiagLevel level;
    int  line, col;
    char phase[16];        /* "lexer", "parser", "semantic", "limits" */
    char message[256];
    char hint[256];
} Diag;

typedef struct { Diag *items; int count, cap; } DiagList;

void diag_init(DiagList *d);
void diag_free(DiagList *d);
void diag_add(DiagList *d, DiagLevel lvl, int line, int col, const char *phase,
              const char *hint, const char *fmt, ...);
int  diag_errors(const DiagList *d);
/* Stable sort by (line, col) so the report reads top-to-bottom. */
void diag_sort(DiagList *d);

#endif
