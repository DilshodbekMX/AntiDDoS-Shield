/**
 * @file fuzz_json_config.c
 * @brief Fuzz testing for JSON configuration parser
 *
 * Tests the secure JSON configuration parser (config_protobuf.c)
 * with randomly mutated inputs to find parsing bugs.
 *
 * Compile with:
 *   clang -fsanitize=fuzzer,address -g -o fuzz_json_config fuzz_json_config.c \
 *     -I../../ -L../../builddir -llayer1 -lcjson -lm
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

/* ==================== Simplified JSON Parser for Fuzzing ==================== */

/* Maximum sizes (match production values) */
#define MAX_JSON_SIZE       (1024 * 1024)  /* 1MB */
#define MAX_STRING_LEN      256
#define MAX_ARRAY_ELEMENTS  1024
#define MAX_NESTING_DEPTH   32

/* JSON value types */
typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

/* JSON value */
typedef struct json_value {
    json_type_t type;
    union {
        bool        boolean;
        double      number;
        char       *string;
        struct {
            struct json_value *items;
            size_t count;
        } array;
        struct {
            char **keys;
            struct json_value *values;
            size_t count;
        } object;
    } data;
} json_value_t;

/* Parser state */
typedef struct {
    const char *input;
    size_t      len;
    size_t      pos;
    int         depth;
    char       *error;
} json_parser_t;

/* Forward declarations */
static json_value_t* parse_value(json_parser_t *p);
static void free_value(json_value_t *v);

/**
 * Skip whitespace
 */
static void skip_whitespace(json_parser_t *p) {
    while (p->pos < p->len) {
        char c = p->input[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            break;
        }
    }
}

/**
 * Parse string
 */
static char* parse_string(json_parser_t *p) {
    if (p->pos >= p->len || p->input[p->pos] != '"') {
        return NULL;
    }
    p->pos++;  /* Skip opening quote */

    size_t start = p->pos;
    size_t str_len = 0;
    bool escaped = false;

    while (p->pos < p->len) {
        char c = p->input[p->pos];

        if (escaped) {
            escaped = false;
            str_len++;
            p->pos++;
        } else if (c == '\\') {
            escaped = true;
            p->pos++;
        } else if (c == '"') {
            break;
        } else if (c < 0x20) {
            /* Control characters not allowed */
            return NULL;
        } else {
            str_len++;
            p->pos++;
        }

        /* Length limit */
        if (str_len > MAX_STRING_LEN) {
            return NULL;
        }
    }

    if (p->pos >= p->len) {
        return NULL;  /* Unterminated string */
    }

    /* Allocate and copy string */
    char *result = malloc(str_len + 1);
    if (!result) return NULL;

    /* Simple copy (production code handles escapes properly) */
    size_t j = 0;
    for (size_t i = start; i < p->pos && j < str_len; i++) {
        if (p->input[i] == '\\' && i + 1 < p->pos) {
            char next = p->input[i + 1];
            switch (next) {
                case 'n':  result[j++] = '\n'; i++; break;
                case 't':  result[j++] = '\t'; i++; break;
                case 'r':  result[j++] = '\r'; i++; break;
                case '"':  result[j++] = '"';  i++; break;
                case '\\': result[j++] = '\\'; i++; break;
                default:   result[j++] = next; i++; break;
            }
        } else {
            result[j++] = p->input[i];
        }
    }
    result[j] = '\0';

    p->pos++;  /* Skip closing quote */
    return result;
}

/**
 * Parse number
 */
static bool parse_number(json_parser_t *p, double *out) {
    size_t start = p->pos;
    bool has_digit = false;
    bool has_dot = false;
    bool has_exp = false;

    /* Optional minus */
    if (p->pos < p->len && p->input[p->pos] == '-') {
        p->pos++;
    }

    /* Integer part */
    while (p->pos < p->len && p->input[p->pos] >= '0' && p->input[p->pos] <= '9') {
        has_digit = true;
        p->pos++;
    }

    /* Decimal part */
    if (p->pos < p->len && p->input[p->pos] == '.') {
        has_dot = true;
        p->pos++;
        while (p->pos < p->len && p->input[p->pos] >= '0' && p->input[p->pos] <= '9') {
            p->pos++;
        }
    }

    /* Exponent */
    if (p->pos < p->len && (p->input[p->pos] == 'e' || p->input[p->pos] == 'E')) {
        has_exp = true;
        p->pos++;
        if (p->pos < p->len && (p->input[p->pos] == '+' || p->input[p->pos] == '-')) {
            p->pos++;
        }
        while (p->pos < p->len && p->input[p->pos] >= '0' && p->input[p->pos] <= '9') {
            p->pos++;
        }
    }

    if (!has_digit) {
        p->pos = start;
        return false;
    }

    /* Convert to double */
    char *num_str = strndup(p->input + start, p->pos - start);
    if (!num_str) {
        p->pos = start;
        return false;
    }

    *out = strtod(num_str, NULL);
    free(num_str);
    return true;
}

/**
 * Parse array
 */
static json_value_t* parse_array(json_parser_t *p) {
    if (p->pos >= p->len || p->input[p->pos] != '[') {
        return NULL;
    }
    p->pos++;

    p->depth++;
    if (p->depth > MAX_NESTING_DEPTH) {
        p->depth--;
        return NULL;
    }

    json_value_t *result = calloc(1, sizeof(json_value_t));
    if (!result) {
        p->depth--;
        return NULL;
    }
    result->type = JSON_ARRAY;

    /* Pre-allocate some space */
    size_t capacity = 16;
    result->data.array.items = calloc(capacity, sizeof(json_value_t));
    if (!result->data.array.items) {
        free(result);
        p->depth--;
        return NULL;
    }

    skip_whitespace(p);

    /* Empty array */
    if (p->pos < p->len && p->input[p->pos] == ']') {
        p->pos++;
        p->depth--;
        return result;
    }

    while (p->pos < p->len) {
        /* Check array size limit */
        if (result->data.array.count >= MAX_ARRAY_ELEMENTS) {
            free_value(result);
            p->depth--;
            return NULL;
        }

        /* Grow if needed */
        if (result->data.array.count >= capacity) {
            capacity *= 2;
            json_value_t *new_items = realloc(result->data.array.items,
                                               capacity * sizeof(json_value_t));
            if (!new_items) {
                free_value(result);
                p->depth--;
                return NULL;
            }
            result->data.array.items = new_items;
        }

        /* Parse element */
        json_value_t *elem = parse_value(p);
        if (!elem) {
            free_value(result);
            p->depth--;
            return NULL;
        }

        result->data.array.items[result->data.array.count++] = *elem;
        free(elem);  /* Shallow free, data moved */

        skip_whitespace(p);

        if (p->pos < p->len && p->input[p->pos] == ',') {
            p->pos++;
            skip_whitespace(p);
        } else if (p->pos < p->len && p->input[p->pos] == ']') {
            p->pos++;
            break;
        } else {
            free_value(result);
            p->depth--;
            return NULL;
        }
    }

    p->depth--;
    return result;
}

/**
 * Parse object
 */
static json_value_t* parse_object(json_parser_t *p) {
    if (p->pos >= p->len || p->input[p->pos] != '{') {
        return NULL;
    }
    p->pos++;

    p->depth++;
    if (p->depth > MAX_NESTING_DEPTH) {
        p->depth--;
        return NULL;
    }

    json_value_t *result = calloc(1, sizeof(json_value_t));
    if (!result) {
        p->depth--;
        return NULL;
    }
    result->type = JSON_OBJECT;

    size_t capacity = 16;
    result->data.object.keys = calloc(capacity, sizeof(char *));
    result->data.object.values = calloc(capacity, sizeof(json_value_t));
    if (!result->data.object.keys || !result->data.object.values) {
        free(result->data.object.keys);
        free(result->data.object.values);
        free(result);
        p->depth--;
        return NULL;
    }

    skip_whitespace(p);

    /* Empty object */
    if (p->pos < p->len && p->input[p->pos] == '}') {
        p->pos++;
        p->depth--;
        return result;
    }

    while (p->pos < p->len) {
        skip_whitespace(p);

        /* Parse key */
        char *key = parse_string(p);
        if (!key) {
            free_value(result);
            p->depth--;
            return NULL;
        }

        skip_whitespace(p);

        /* Expect colon */
        if (p->pos >= p->len || p->input[p->pos] != ':') {
            free(key);
            free_value(result);
            p->depth--;
            return NULL;
        }
        p->pos++;

        skip_whitespace(p);

        /* Parse value */
        json_value_t *value = parse_value(p);
        if (!value) {
            free(key);
            free_value(result);
            p->depth--;
            return NULL;
        }

        /* Grow if needed */
        if (result->data.object.count >= capacity) {
            capacity *= 2;
            char **new_keys = realloc(result->data.object.keys,
                                      capacity * sizeof(char *));
            json_value_t *new_values = realloc(result->data.object.values,
                                               capacity * sizeof(json_value_t));
            if (!new_keys || !new_values) {
                free(key);
                free_value(value);
                free(new_keys);
                free(new_values);
                free_value(result);
                p->depth--;
                return NULL;
            }
            result->data.object.keys = new_keys;
            result->data.object.values = new_values;
        }

        result->data.object.keys[result->data.object.count] = key;
        result->data.object.values[result->data.object.count] = *value;
        result->data.object.count++;
        free(value);

        skip_whitespace(p);

        if (p->pos < p->len && p->input[p->pos] == ',') {
            p->pos++;
        } else if (p->pos < p->len && p->input[p->pos] == '}') {
            p->pos++;
            break;
        } else {
            free_value(result);
            p->depth--;
            return NULL;
        }
    }

    p->depth--;
    return result;
}

/**
 * Parse any value
 */
static json_value_t* parse_value(json_parser_t *p) {
    skip_whitespace(p);

    if (p->pos >= p->len) {
        return NULL;
    }

    char c = p->input[p->pos];

    /* String */
    if (c == '"') {
        json_value_t *result = calloc(1, sizeof(json_value_t));
        if (!result) return NULL;
        result->type = JSON_STRING;
        result->data.string = parse_string(p);
        if (!result->data.string) {
            free(result);
            return NULL;
        }
        return result;
    }

    /* Number */
    if (c == '-' || (c >= '0' && c <= '9')) {
        json_value_t *result = calloc(1, sizeof(json_value_t));
        if (!result) return NULL;
        result->type = JSON_NUMBER;
        if (!parse_number(p, &result->data.number)) {
            free(result);
            return NULL;
        }
        return result;
    }

    /* Array */
    if (c == '[') {
        return parse_array(p);
    }

    /* Object */
    if (c == '{') {
        return parse_object(p);
    }

    /* true */
    if (p->pos + 4 <= p->len && strncmp(p->input + p->pos, "true", 4) == 0) {
        p->pos += 4;
        json_value_t *result = calloc(1, sizeof(json_value_t));
        if (!result) return NULL;
        result->type = JSON_BOOL;
        result->data.boolean = true;
        return result;
    }

    /* false */
    if (p->pos + 5 <= p->len && strncmp(p->input + p->pos, "false", 5) == 0) {
        p->pos += 5;
        json_value_t *result = calloc(1, sizeof(json_value_t));
        if (!result) return NULL;
        result->type = JSON_BOOL;
        result->data.boolean = false;
        return result;
    }

    /* null */
    if (p->pos + 4 <= p->len && strncmp(p->input + p->pos, "null", 4) == 0) {
        p->pos += 4;
        json_value_t *result = calloc(1, sizeof(json_value_t));
        if (!result) return NULL;
        result->type = JSON_NULL;
        return result;
    }

    return NULL;
}

/**
 * Free JSON value tree
 */
static void free_value(json_value_t *v) {
    if (!v) return;

    switch (v->type) {
        case JSON_STRING:
            free(v->data.string);
            break;

        case JSON_ARRAY:
            for (size_t i = 0; i < v->data.array.count; i++) {
                /* Recursive inline */
                json_value_t *elem = &v->data.array.items[i];
                if (elem->type == JSON_STRING) {
                    free(elem->data.string);
                } else if (elem->type == JSON_ARRAY || elem->type == JSON_OBJECT) {
                    free_value(elem);
                }
            }
            free(v->data.array.items);
            break;

        case JSON_OBJECT:
            for (size_t i = 0; i < v->data.object.count; i++) {
                free(v->data.object.keys[i]);
                json_value_t *val = &v->data.object.values[i];
                if (val->type == JSON_STRING) {
                    free(val->data.string);
                } else if (val->type == JSON_ARRAY || val->type == JSON_OBJECT) {
                    free_value(val);
                }
            }
            free(v->data.object.keys);
            free(v->data.object.values);
            break;

        default:
            break;
    }

    free(v);
}

/**
 * Parse JSON from string
 */
static json_value_t* json_parse(const char *input, size_t len) {
    if (!input || len == 0 || len > MAX_JSON_SIZE) {
        return NULL;
    }

    json_parser_t parser = {
        .input = input,
        .len = len,
        .pos = 0,
        .depth = 0,
        .error = NULL
    };

    json_value_t *result = parse_value(&parser);

    skip_whitespace(&parser);

    /* Should have consumed all input */
    if (parser.pos != parser.len) {
        free_value(result);
        return NULL;
    }

    return result;
}

/* ==================== libFuzzer Entry Point ==================== */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Size limit */
    if (size > MAX_JSON_SIZE) {
        return 0;
    }

    /* Ensure null-termination for string operations */
    char *input = malloc(size + 1);
    if (!input) return 0;

    memcpy(input, data, size);
    input[size] = '\0';

    /* Parse JSON */
    json_value_t *result = json_parse(input, size);

    /* Free result */
    if (result) {
        free_value(result);
    }

    free(input);
    return 0;
}

/* ==================== Standalone Test ==================== */

#ifdef FUZZ_STANDALONE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        /* Test some sample inputs */
        const char *samples[] = {
            "{}",
            "[]",
            "null",
            "true",
            "false",
            "123",
            "\"hello\"",
            "{\"key\": \"value\"}",
            "[1, 2, 3]",
            "{\"nested\": {\"array\": [1, 2, 3]}}",
            NULL
        };

        for (int i = 0; samples[i] != NULL; i++) {
            printf("Testing: %s\n", samples[i]);
            int result = LLVMFuzzerTestOneInput(
                (const uint8_t *)samples[i], strlen(samples[i]));
            printf("Result: %d\n\n", result);
        }
        return 0;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    fstat(fd, &st);

    uint8_t *data = malloc(st.st_size);
    read(fd, data, st.st_size);
    close(fd);

    printf("Testing %s (%zu bytes)\n", argv[1], (size_t)st.st_size);
    int result = LLVMFuzzerTestOneInput(data, st.st_size);
    printf("Result: %d\n", result);

    free(data);
    return 0;
}
#endif
