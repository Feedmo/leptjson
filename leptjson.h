#ifndef LEPTJSON_H__
#define LEPTJSON_H__

#include <crtdefs.h>

typedef enum { LEPT_NULL, LEPT_FALSE, LEPT_TRUE, LEPT_NUMBER, LEPT_STRING, LEPT_ARRAY, LEPT_OBJECT } lept_type;

enum {
    LEPT_PARSE_OK,
    LEPT_PARSE_INVALID_VALUE,
    LEPT_PARSE_EXPECT_VALUE,
    LEPT_PARSE_ROOT_NOT_SINGULAR,
    LEPT_PARSE_NUMBER_TOO_BIG,
    LEPT_PARSE_MISS_QUOTATION_MARK,
    LEPT_PARSE_INVALID_STRING_ESCAPE,
    LEPT_PARSE_INVALID_STRING_CHAR,
    LEPT_PARSE_INVALID_UNICODE_HEX,
    LEPT_PARSE_INVALID_UNICODE_SURROGATE,
};

// NOTE:  do { ... } while(0) 是为了把表达式转为语句，模仿无返回值的函数
#define lept_init(v) do { (v)->type = LEPT_NULL; } while(0) 
// TODO: this place ok ?
#define lept_set_null(v) lept_free(v)

typedef struct {
    union {
        struct { char* s; size_t len; } s;  /* string */
        double n;                           /* number */
    } u;
    lept_type type;
} lept_value;

void lept_free(lept_value* v);

int lept_parse(lept_value* v, const char* json);

int lept_get_boolean(const lept_value* v);
void lept_set_boolean(lept_value* v, int b);

double lept_get_number(const lept_value* v);
void lept_set_number(lept_value* v, double n);

const char* lept_get_string(const lept_value* v);
size_t lept_get_string_length(const lept_value* v);
void lept_set_string(lept_value* v, const char* s, size_t len);

lept_type lept_get_type(const lept_value* v);

#endif 
