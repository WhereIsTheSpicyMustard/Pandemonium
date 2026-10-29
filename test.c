#include "pandemonium.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  uint32_t md[8];
  char *msg;
  size_t len;
} sha256test_t;

typedef struct {
  uint64_t md[8];
  char *msg;
  size_t len;
} sha512test_t;

sha256test_t sha256_tests[] = {
    #include "sha256tests.inc"
};

static sha512test_t sha512_tests[] = {
    #include "sha512tests.inc"
};

static uint8_t parse_char(const char c)
{
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= '0' && c <= '9')
        return c - '0';
    assert(0);
}

static int test256(const sha256test_t* const test)
{
    assert(test != NULL);
    assert(((test->len) & 1) == 0);
    if (test->len == 0) {
        printf("md:          ");
        uint32_t hash[8] = {0};
        if (pandemonium_sha256(hash, test->msg, 0))
            return 1;
        for (int i = 0; i < 8; ++i) {
            printf("%08x", hash[i]);
            assert(hash[i] == test->md[i]);
        }
        printf("\n");
        return 0;
    }
    const size_t new_len = test->len / 8;
    uint8_t* msg_cpy = malloc(new_len);
    if (msg_cpy == NULL) return 1;
    size_t j = 0;
    for (size_t i = 0;; i += 2) {
        if (test->msg[i] == '\0')
            break;
        assert(test->msg[i + 1] != '\0');

        assert(j < new_len);
        msg_cpy[j++] = (parse_char(test->msg[i]) << 4) | parse_char(test->msg[i + 1]);
    }

    uint32_t hash[8] = {0};
    if (pandemonium_sha256(hash, msg_cpy, new_len))
        return 1;
    printf("md:          ");
    for (int i = 0; i < 8; ++i) {
        printf("%08x", hash[i]);
        assert(hash[i] == test->md[i]);
    }
    printf("\n");

    free(msg_cpy);
    return 0;
}

int main(void)
{
    for (size_t i = 0; i < sizeof(sha256_tests) / sizeof(sha256_tests[0]); ++i) {
        printf("\n\nTest %zu\n", i);
        printf("msg:\n");
        for (int j = 0; sha256_tests[i].msg[j] != '\0'; ++j) {
            printf("%c", sha256_tests[i].msg[j]);
            if (((j + 1) % 80) == 0) printf("\n");
        }
        printf("\n\nExpected md: ");
        for (int j = 0; j < 8; ++j)
            printf("%08x", sha256_tests[i].md[j]);
        printf("\n");
        if (test256(sha256_tests + i)) {
            printf("\nsomething went wrong\n");
            return 1;
        }
    }

    return 0;
}
