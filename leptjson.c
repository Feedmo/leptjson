#include <assert.h>
#include <crtdefs.h>
#include <stdlib.h> /* NULL, strtod() */
#include <math.h>   /* HUGE_VAL */
#include <errno.h>  /* errno, REANGE */
#include <string.h>
#include "leptjson.h"

#define EXPECT(c, ch) do { assert(*c->json == (ch)); c->json++; } while(0)
#define IS_DIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')
#define IS_DIGIT(ch) ((ch) >= '0' && (ch) <= '9')
// REVIEW: important
#define PUTC(c, ch) do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

typedef struct {
    const char* json;
    char* stack;
    size_t top, size;
} lept_context;

static void lept_parse_whitespace(lept_context* c) {
    const char* p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* str, lept_type type) {
    EXPECT(c, *str);
    str++;
    while (*str) {
        if (*c->json != *str)
            return LEPT_PARSE_INVALID_VALUE;
        c->json++;
        str++;
    }   
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    const char* p = c->json;
    if (*p == '-') p++;
    if (*p == '0') p++;
    else {
        if (!IS_DIGIT1TO9(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; IS_DIGIT(*p); p++);
    }
    if (*p == '.') {
        p++;
        if (!IS_DIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; IS_DIGIT(*p); p++);   
    }
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        if (!IS_DIGIT(*p)) return LEPT_PARSE_INVALID_VALUE;
        for (p++; IS_DIGIT(*p); p++); 
    }
    errno = 0;
    v->u.n = strtod(c->json, NULL);
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL))
        return LEPT_PARSE_NUMBER_TOO_BIG;
    c->json = p;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static void* lept_context_push(lept_context* c, size_t size) {
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;
        c->stack = (char*)realloc(c->stack, c->size);
    }
    void* ret = c->stack + c->top;  // REVIEW: now the stack data start from here
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    *u = 0;
    for (size_t i=0; i<4; i++) {
        char ch = *p++;
        *u <<= 4;
        if (ch >= '0' && ch <= '9') *u |= ch - '0';
        else if (ch >= 'A' && ch <= 'F') *u |= ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'z') *u |= ch - 'a' + 10;
        else return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    if (u <= 0x7F) {
        PUTC(c, u & 0xFF);
    } else if (u <= 0x7FF) {
        PUTC(c, 0xC0 | ((u >> 6)  & 0xFF)); // 更缺切实0x1F，但因为右移前面会补零，因此使用0xFF结果一样
        PUTC(c, 0x80 | (u         & 0x3F));
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0 | ((u >> 12) & 0xFF));
        PUTC(c, 0x80 | ((u >> 6)  & 0x3F));
        PUTC(c, 0x80 | (u         & 0x3F));
    } else {
        assert(u <= 0x10FFFF);
        PUTC(c, 0xF0 | ((u >> 18) & 0xFF));
        PUTC(c, 0x80 | ((u >> 12) & 0x3F));
        PUTC(c, 0x80 | ((u >>  6) & 0x3F));
        PUTC(c, 0x80 | ( u        & 0x3F));
    }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)
static int lept_parse_string(lept_context* c, lept_value* v) {
    EXPECT(c, '\"');
    size_t head = c->top, len;
    unsigned u, u2;
    const char* p = c->json;
    for(;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char*)lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
                ch = *p++;
                switch (ch) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/': PUTC(c, '/'); break;
                    case 'b': PUTC(c, '\b'); break;
                    case 'f': PUTC(c, '\f'); break;
                    case 'n': PUTC(c, '\n'); break;
                    case 'r': PUTC(c, '\r'); break;
                    case 't': PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        /* surrogate pair */
                        if (u >= 0xD800 && u <= 0xDBFF) { 
                            if (*p++ != '\\')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            if (!(p = lept_parse_hex4(p, &u2)))
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            u = (((u - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int lept_parse_value(lept_context* c, lept_value* v);

// [ v1 , v2 ]
static int lept_parse_array(lept_context* c, lept_value* v) {
    EXPECT(c, '[');
    int ret;
    size_t size = 0;
    lept_parse_whitespace(c);

    if (*c->json == ']') {
        c->json++;
        v->u.a.e = NULL;
        v->u.a.size = 0;
        v->type = LEPT_ARRAY;
        return LEPT_PARSE_OK;
    }
    for (;;) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK)
            break;
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;  // todo: 不能有单独的 ',' 可以带有空格
            lept_parse_whitespace(c);
        }
        else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            size *= sizeof(lept_value);
            memcpy(v->u.a.e = (lept_value*)malloc(size), lept_context_pop(c, size), size);
            return LEPT_PARSE_OK;
        } else {
            ret = LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
            break;
        }
    }
    // note: 防止内存泄漏
    for (size_t i = 0; i<size; i++) {
        lept_free((lept_value*)lept_context_pop(c, sizeof(lept_value)));
    }
    return ret;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 'n': return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't': return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f': return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '"': return lept_parse_string(c, v);
        case '[': return lept_parse_array(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
        default: return lept_parse_number(c, v);
    }
}

int lept_parse(lept_value* v, const char* json) {
    assert(v != NULL);
    lept_context c;
    int ret;
    c.json = json;
    c.stack = NULL;
    c.top = c.size = 0;
    lept_init(v);

    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);  // REVIEW: important!
    return ret;
}

lept_type lept_get_type(const lept_value* v) {
    return v->type;
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    switch (v->type) {
        case LEPT_STRING:
            free(v->u.s.s);
            break;
        case LEPT_ARRAY:
            for (size_t i=0; i< v->u.a.size; i++)
                lept_free(&v->u.a.e[i]);    // note: 递归地free数组元素
            free(v->u.a.e);
            break;
        default: break;
    }
    v->type = LEPT_NULL;    // NOTE: 可以避免重复释放
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

double lept_get_number(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;   
}

void lept_set_boolean(lept_value* v, int b) {
    assert(v != NULL);
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    // 非空指针（有具体的字符串）或是零长度的字符串都是合法的
    assert(v != NULL && (s != NULL || len == 0));  // FIXME: 如果s!=NULL是否已经保证了len>=0 ?
    lept_free(v);
    v->u.s.s = (char*)malloc(len+1);
    memcpy(v->u.s.s, s, len);
    v->u.s.len = len;
    v->u.s.s[len] = '\0';
    v->type = LEPT_STRING;
}

size_t lept_get_string_length(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_array_size(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value* lept_get_array_element(const lept_value* v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);  // TODO: index >= 0 ?
    return &v->u.a.e[index];
}