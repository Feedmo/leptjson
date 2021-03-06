#include "leptjson.h"
#include <stdio.h>
#include <string.h>

/**
 * %g 的含义？
 * 
*/
static int test_count = 0;
static int test_pass = 0;
static int main_ret = 0;

#define LEPT_EQ_BASE(equlity, expect, actual, format) \
    do {\
        test_count++;\
        if (equlity)\
            test_pass++;\
        else {\
            fprintf(stderr, "%s:%d: expect: " format " actual: " format "\n", __FILE__, __LINE__, expect, actual);\
            main_ret = 1;\
        }\
    } while (0)

#define LEPT_EQ_INT(expect, actual) LEPT_EQ_BASE((expect) == (actual), expect, actual, "%d")
#define LEPT_EQ_DOUBLE(expect, actual) LEPT_EQ_BASE((expect) == (actual), expect, actual, "%.17g")
#define LEPT_EQ_STRING(expect, actual, len) \
    LEPT_EQ_BASE(sizeof(expect)-1 == len && memcmp(expect, actual, len) == 0, expect, actual, "%s")
#define EXPECT_TRUE(actual) LEPT_EQ_BASE((actual) != 0, "true", "actual", "%s")
#define EXPECT_FALSE(actual) LEPT_EQ_BASE((actual) == 0, "false", "true", "%s")

static void test_parse_null() {
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 0);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "null"));
    LEPT_EQ_INT(LEPT_NULL, lept_get_type(&v));
    lept_free(&v);
}

static void test_parse_false() {
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 1);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "false"));
    LEPT_EQ_INT(LEPT_FALSE, lept_get_type(&v));
    lept_free(&v);
}

static void test_parse_true() {
    lept_value v;
    lept_init(&v);
    lept_set_boolean(&v, 0);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "true"));
    LEPT_EQ_INT(LEPT_TRUE, lept_get_type(&v));
    lept_free(&v);
}

#define TEST_NUMBER(expect, json) \
    do {\
        lept_value v;\
        LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, json));\
        LEPT_EQ_INT(LEPT_NUMBER, lept_get_type(&v));\
        LEPT_EQ_DOUBLE(expect, lept_get_number(&v));\
    } while(0)

static void test_parse_number() {
    TEST_NUMBER(0.0, "0");
    TEST_NUMBER(0.0, "-0");
    TEST_NUMBER(0.0, "-0.0");
    TEST_NUMBER(1.0, "1");
    TEST_NUMBER(-1.0, "-1");
    TEST_NUMBER(1.5, "1.5");
    TEST_NUMBER(-1.5, "-1.5");
    TEST_NUMBER(3.1416, "3.1416");
    TEST_NUMBER(1E10, "1E10");
    TEST_NUMBER(1e10, "1e10");
    TEST_NUMBER(1E+10, "1E+10");
    TEST_NUMBER(1E-10, "1E-10");
    TEST_NUMBER(-1E10, "-1E10");
    TEST_NUMBER(-1e10, "-1e10");
    TEST_NUMBER(-1E+10, "-1E+10");
    TEST_NUMBER(-1E-10, "-1E-10");
    TEST_NUMBER(1.234E+10, "1.234E+10");
    TEST_NUMBER(1.234E-10, "1.234E-10");
    TEST_NUMBER(0.0, "1e-10000"); /* must underflow */
}

#define TEST_ERROR(error, json) \
    do {\
        lept_value v;\
        v.type = LEPT_NULL;\
        LEPT_EQ_INT(error, lept_parse(&v, json));\
        LEPT_EQ_INT(LEPT_NULL, lept_get_type(&v));\
    } while(0)

static void test_parse_not_singular() {
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "null x");

#if 1
    /* invalid number */
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0123"); /* after zero should be '.' , 'E' , 'e' or nothing */
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0x0");
    TEST_ERROR(LEPT_PARSE_ROOT_NOT_SINGULAR, "0x123");
#endif
}

static void test_parse_invalid_value() {
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "x");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "?");

#if 1
    // invalid number
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "+0");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "+1");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, ".123"); /* at least one digit before '.' */
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "1.");   /* at least one digit after '.' */
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "INF");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "inf");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "NAN");
    TEST_ERROR(LEPT_PARSE_INVALID_VALUE, "nan");
#endif
}

static void test_parse_expect_value() {
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, "");
    TEST_ERROR(LEPT_PARSE_EXPECT_VALUE, " ");
}

static void test_parse_number_too_big() {
#if 1
    TEST_ERROR(LEPT_PARSE_NUMBER_TOO_BIG, "1e309");
    TEST_ERROR(LEPT_PARSE_NUMBER_TOO_BIG, "-1e309");
#endif
}

static void test_access_null() {
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "a", 1);

    lept_set_null(&v);
    LEPT_EQ_INT(LEPT_NULL, lept_get_type(&v));

    lept_free(&v);
}

static void test_access_boolean() {
    lept_value v;
    lept_init(&v);

    lept_set_string(&v, "a", 1);
    lept_set_boolean(&v, 1);
    EXPECT_TRUE(lept_get_boolean(&v));
    lept_set_boolean(&v, 0);
    EXPECT_FALSE(lept_get_boolean(&v));

    lept_free(&v);
}

static void test_access_number() {
    lept_value v;
    lept_init(&v);
    lept_set_string(&v, "a", 1);

    lept_set_number(&v, 2.13);
    LEPT_EQ_DOUBLE(2.13, lept_get_number(&v));

    lept_free(&v);
}

static void test_access_string() {
    lept_value v;
    lept_init(&v);

    lept_set_string(&v, "", 0);
    LEPT_EQ_STRING("", lept_get_string(&v), lept_get_string_length(&v));
    lept_set_string(&v, "hello", 5);
    LEPT_EQ_STRING("hello", lept_get_string(&v), lept_get_string_length(&v));

    lept_free(&v);
}

#define TEST_STRING(expect, json)\
    do {\
        lept_value v;\
        lept_init(&v);\
        LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, json));\
        LEPT_EQ_INT(LEPT_STRING, lept_get_type(&v));\
        LEPT_EQ_STRING(expect, lept_get_string(&v), lept_get_string_length(&v));\
    } while(0)

static void test_parse_string() {
    TEST_STRING("", "\"\"");
    TEST_STRING("Hello", "\"Hello\"");
#if 1
    TEST_STRING("Hello\nWorld", "\"Hello\\nWorld\"");
    TEST_STRING("\" \\ / \b \f \n \r \t", "\"\\\" \\\\ \\/ \\b \\f \\n \\r \\t\"");
#endif
}

#define EXPECT_EQ_SIZE_T(expect, actual) LEPT_EQ_BASE((expect) == (actual), (size_t)expect, (size_t)actual, "%zu")
static void test_parse_array() {
    lept_value v;
    lept_init(&v);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ ]"));
    LEPT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    EXPECT_EQ_SIZE_T(0, lept_get_array_size(&v));
    lept_free(&v);

    lept_init(&v);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ null , false , true , 123 , \"abc\" ]"));
    LEPT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    EXPECT_EQ_SIZE_T(5, lept_get_array_size(&v));
    LEPT_EQ_INT(LEPT_NULL, lept_get_type(lept_get_array_element(&v, 0)));
    LEPT_EQ_INT(LEPT_FALSE, lept_get_type(lept_get_array_element(&v, 1)));
    LEPT_EQ_INT(LEPT_TRUE, lept_get_type(lept_get_array_element(&v, 2)));
    LEPT_EQ_INT(LEPT_NUMBER, lept_get_type(lept_get_array_element(&v, 3)));
    LEPT_EQ_INT(LEPT_STRING, lept_get_type(lept_get_array_element(&v, 4)));
    LEPT_EQ_DOUBLE(123.0, lept_get_number(lept_get_array_element(&v, 3)));
    LEPT_EQ_STRING("abc", lept_get_string(lept_get_array_element(&v, 4)), lept_get_string_length(lept_get_array_element(&v, 4)));
    lept_free(&v);

    lept_init(&v);
    LEPT_EQ_INT(LEPT_PARSE_OK, lept_parse(&v, "[ [ ] , [ 0 ] , [ 0 , 1 ] , [ 0 , 1 , 2 ] ]"));
    LEPT_EQ_INT(LEPT_ARRAY, lept_get_type(&v));
    EXPECT_EQ_SIZE_T(4, lept_get_array_size(&v));
    for (size_t i=0; i<4; i++) {
        lept_value* a = lept_get_array_element(&v, i);
        LEPT_EQ_INT(LEPT_ARRAY, lept_get_type(a));
        EXPECT_EQ_SIZE_T(i, lept_get_array_size(a));
        for (size_t j=0; j<i; j++) {
            lept_value* e = lept_get_array_element(a, j);
            LEPT_EQ_INT(LEPT_NUMBER, lept_get_type(e));
            LEPT_EQ_DOUBLE((double)j, lept_get_number(e));
        }
    }
    lept_free(&v);
}

static void test_parse_invalid_string_escape() {
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\v\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\'\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\0\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE, "\"\\x12\"");
}

static void test_parse_invalid_string_char() {
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_CHAR, "\"\x01\"");
    TEST_ERROR(LEPT_PARSE_INVALID_STRING_CHAR, "\"\x1F\"");
}

static void test_parse_array_miss_comma_or_square_bracket() {
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1}");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[1 2");
    TEST_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET, "[[]");
}

static void test_parse() {
    test_parse_null();
    test_parse_true();
    test_parse_false();
    test_parse_number();
    test_parse_string();
    test_parse_array();

    test_access_string();
    test_access_boolean();
    test_access_null();
    test_access_number();
    
    test_parse_not_singular();
    test_parse_expect_value();
    test_parse_invalid_value();
    test_parse_number_too_big();
    test_parse_invalid_string_char();
    test_parse_invalid_string_escape();
    test_parse_array_miss_comma_or_square_bracket();
}

int main() {
    test_parse();
    printf("%d/%d (%3.2f%%) passed\n", test_pass, test_count, test_pass * 100.0 / test_count);
    return main_ret;
}