#include "pandemonium.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>

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

uint64_t pandemonium_splitmix64_next(void)
{
    uint64_t z = (splitmix_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

uint64_t pandemonium_splitmix64(const uint64_t x)
{
    uint64_t z = (x + 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

// initial seed must be nonzero
void pandemonium_xorshift64star_set_state(const uint64_t x)
{
    xorshift_state = x;
}

uint64_t pandemonium_xorshift64star_next(void)
{
    xorshift_state ^= xorshift_state >> 12;
    xorshift_state ^= xorshift_state << 25;
    xorshift_state ^= xorshift_state >> 27;
    return xorshift_state * 0x2545F4914F6CDD1DULL;
}

// x must be nonzero
uint64_t pandemonium_xorshift64star(uint64_t x)
{
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1DULL;
}

/*******************************************************/

int pandemonium_csprng_uint8(uint8_t* buf)
{
    return (getrandom(buf, sizeof(*buf), 0) != sizeof(*buf));
}

int pandemonium_csprng_uint16(uint16_t* buf)
{
    return (getrandom(buf, sizeof(*buf), 0) != sizeof(*buf));
}

int pandemonium_csprng_uint32(uint32_t* buf)
{
    return (getrandom(buf, sizeof(*buf), 0) != sizeof(*buf));
}

int pandemonium_csprng_uint64(uint64_t* buf)
{
    return (getrandom(buf, sizeof(*buf), 0) != sizeof(*buf));
}

/*******************************************************/

int pandemonium_csprng_uint8_arr(uint8_t* buf, const size_t count)
{
    const size_t size = count * sizeof(*buf);
    if (buf == NULL || count > (256 / sizeof(*buf)))
        return 1;
    return ((ssize_t)size != getrandom(buf, size, 0));
}

int pandemonium_csprng_uint16_arr(uint16_t* buf, const size_t count)
{
    const size_t size = count * sizeof(*buf);
    if (buf == NULL || count > (256 / sizeof(*buf)))
        return 1;
    return ((ssize_t)size != getrandom(buf, size, 0));
}

int pandemonium_csprng_uint32_arr(uint32_t* buf, const size_t count)
{
    const size_t size = count * sizeof(*buf);
    if (buf == NULL || count > (256 / sizeof(*buf)))
        return 1;
    return ((ssize_t)size != getrandom(buf, size, 0));
}

int pandemonium_csprng_uint64_arr(uint64_t* buf, const size_t count)
{
    const size_t size = count * sizeof(*buf);
    if (buf == NULL || count > (256 / sizeof(*buf)))
        return 1;
    return ((ssize_t)size != getrandom(buf, size, 0));
}

/*******************************************************/

// Returns 0 on sucess
int pandemonium_csprng_uint8_range(uint8_t* buf, const size_t count, const uint8_t max) 
{
    if (max == 0 || buf == NULL)
        return 1;

    const int bits = 32 - __builtin_clz((unsigned int)max);
    const uint8_t mask = (uint8_t)((bits == 8) ? (UINT8_MAX) : ((1u << bits) - 1u));

    for (size_t i = 0; i < count; ++i) {
        do {
            if (sizeof(*buf) != getrandom(buf + i, sizeof(*buf), 0))
                return 1;
            buf[i] &= mask;
        } while (buf[i] > max);
    }
    return 0;
}


int pandemonium_csprng_uint16_range(uint16_t* buf, const size_t count, const uint16_t max) 
{
    if (max == 0 || buf == NULL)
        return 1;

    const int bits = 32 - __builtin_clz((unsigned int)max);
    const uint16_t mask = (uint16_t)((bits == 16) ? (UINT16_MAX) : ((1U << bits) - 1U));

    for (size_t i = 0; i < count; ++i) {
        do {
            if (sizeof(*buf) != getrandom(buf + i, sizeof(*buf), 0))
                return 1;
            buf[i] &= mask;
        } while (buf[i] > max);
    }
    return 0;
}

int pandemonium_csprng_uint32_range(uint32_t* buf, const size_t count, const uint32_t max) 
{
    if (max == 0 || buf == NULL)
        return 1;

    const int bits = 32 - __builtin_clz(max);
    const uint32_t mask = (bits == 32) ? (UINT32_MAX) : ((1U << bits) - 1U);

    for (size_t i = 0; i < count; ++i) {
        do {
            if (sizeof(*buf) != getrandom(buf + i, sizeof(*buf), 0))
                return 1;
            buf[i] &= mask;
        } while (buf[i] > max);
    }
    return 0;
}

int pandemonium_csprng_uint64_range(uint64_t* buf, const size_t count, const uint64_t max) 
{
    if (max == 0 || buf == NULL)
        return 1;

    const int bits = 64 - __builtin_clzl(max);
    const uint64_t mask = (bits == 64) ? (UINT64_MAX) : ((1UL << bits) - 1UL);

    for (size_t i = 0; i < count; ++i) {
        do {
            if (sizeof(*buf) != getrandom(buf + i, sizeof(*buf), 0))
                return 1;
            buf[i] &= mask;
        } while (buf[i] > max);
    }
    return 0;
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


