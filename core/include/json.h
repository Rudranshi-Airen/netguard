/*
 * json.h -- Minimal streaming JSON writer.
 */
#ifndef NG_JSON_H
#define NG_JSON_H

#include <stdint.h>
#include "util.h"

#define JSON_MAX_DEPTH 64

typedef struct {
    StrBuf sb;
    int depth;
    int count[JSON_MAX_DEPTH];   /* values written at each nesting level */
    int after_key;
} Json;

void  json_init(Json *j);
void  json_free(Json *j);
char *json_take(Json *j);         /* caller frees */

void json_obj(Json *j);           /* { */
void json_end_obj(Json *j);       /* } */
void json_arr(Json *j);           /* [ */
void json_end_arr(Json *j);       /* ] */
void json_key(Json *j, const char *k);
void json_str(Json *j, const char *s);
void json_int(Json *j, long long v);
void json_u64(Json *j, uint64_t v);
void json_num(Json *j, double v);
void json_bool(Json *j, int v);
void json_null(Json *j);

/* key + value shorthands */
void json_kstr(Json *j, const char *k, const char *s);
void json_kint(Json *j, const char *k, long long v);
void json_ku64(Json *j, const char *k, uint64_t v);
void json_knum(Json *j, const char *k, double v);
void json_kbool(Json *j, const char *k, int v);
void json_knull(Json *j, const char *k);

#endif
