#include "pandemonium.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

#define REPORT_ERROR(X) fprintf(stderr, "%s | %s | %d\n", X, __FILE__, __LINE__)

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) do {      \
a += b; d ^= a; d = ROTL(d, 16); \
c += d; b ^= c; b = ROTL(b, 12); \
a += b; d ^= a; d = ROTL(d,  8); \
c += d; b ^= c; b = ROTL(b,  7); \
} while (0)

#define ROUNDS 20

static uint64_t splitmix_state = 0;
static uint64_t xorshift_state = 1;

void pandemonium_splitmix64_set_state(const uint64_t x)
{
    splitmix_state = x;
}

uint64_t pandemonium_splitmix64(void)
{
    uint64_t z = (splitmix_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint64_t pandemonium_splitmix64_next(uint64_t x)
{
    x = (x + 0x9e3779b97f4a7c15ULL);
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

/*******************************************************/

// initial seed must be nonzero
void pandemonium_xorshift64star_set_state(const uint64_t x)
{
    xorshift_state = x;
}

uint64_t pandemonium_xorshift64star(void)
{
    xorshift_state ^= xorshift_state >> 12;
    xorshift_state ^= xorshift_state << 25;
    xorshift_state ^= xorshift_state >> 27;
    return xorshift_state * 0x2545F4914F6CDD1DULL;
}

uint64_t pandemonium_xorshift64star_next(uint64_t x)
{
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1DULL;
}

/*******************************************************/

uint8_t pandemonium_csprng_uint8(void)
{
    uint8_t buf;

    if (getrandom(&buf, sizeof(buf), 0) != sizeof(buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

uint16_t pandemonium_csprng_uint16(void)
{
    uint16_t buf;

    if (getrandom(&buf, sizeof(buf), 0) != sizeof(buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

uint32_t pandemonium_csprng_uint32(void)
{
    uint32_t buf;

    if (getrandom(&buf, sizeof(buf), 0) != sizeof(buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

uint64_t pandemonium_csprng_uint64(void)
{
    uint64_t buf;

    if (getrandom(&buf, sizeof(buf), 0) != sizeof(buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

/*******************************************************/

uint8_t* pandemonium_csprng_uint8_arr(const size_t count)
{
    uint8_t* buf = malloc(count * sizeof(*buf));
    if (buf == NULL) {
        REPORT_ERROR("ERROR: malloc failed");
        return NULL;
    }

    if (getrandom(&buf, sizeof(*buf), 0) != sizeof(*buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return NULL;
    }

    return buf;
}

uint16_t* pandemonium_csprng_uint16_arr(const size_t count)
{
    uint16_t* buf = malloc(count * sizeof(*buf));

    if (buf == NULL) {
        REPORT_ERROR("ERROR: malloc failed");
        return NULL;
    }

    if (getrandom(&buf, sizeof(*buf), 0) != sizeof(*buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

uint32_t* pandemonium_csprng_uint32_arr(const size_t count)
{
    uint32_t* buf = malloc(count * sizeof(*buf));

    if (buf == NULL) {
        REPORT_ERROR("ERROR: malloc failed");
        return NULL;
    }

    if (getrandom(&buf, sizeof(*buf), 0) != sizeof(*buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

uint64_t* pandemonium_csprng_uint64_arr(const size_t count)
{
    uint64_t* buf = malloc(count * sizeof(*buf));

    if (buf == NULL) {
        REPORT_ERROR("ERROR: malloc failed");
        return NULL;
    }

    if (getrandom(&buf, sizeof(*buf), 0) != sizeof(*buf)) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    return buf;
}

/*******************************************************/

uint64_t pandemonium_get_range(const uint64_t min, const uint64_t max)
{
    return min + (pandemonium_csprng_uint64() % (max - min));
}

double pandemonium_get_double(void)
{
    uint64_t buf = ~(1ULL);

    if (getrandom(&buf, 8, 0) != 8) {
        REPORT_ERROR("ERROR: getrandom() failed");
        return 0;
    }

    buf = (0x3FFULL << 52) | (buf >> 12);
    return *((double*)(&buf)) - 1.0;
}

/*******************************************************/

static void pandemonium_chacha_block(uint32_t out[16], uint32_t const in[16])
{
    uint32_t x[16];

    for (int i = 0; i < 16; ++i)
        x[i] = in[i];
    for (int i = 0; i < ROUNDS; i += 2) {
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }
    for (int i = 0; i < 16; ++i)
        out[i] = x[i] + in[i];
}


