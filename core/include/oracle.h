/*
 * oracle.h -- Reference first-match evaluator (verification only).
 */
#ifndef NG_ORACLE_H
#define NG_ORACLE_H

#include "ir.h"

/* Returns the decided action; *winner (optional) gets the rule index or -1. */
int oracle_eval(const Policy *p, const uint32_t *vals, int *winner);

#endif
