#include "pandemonium.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <assert.h>
#include <errno.h>

#define U64(c) UINT64_C(c)

typedef unsigned char uchar;

static uint64_t splitmix_state = 0;
static uint64_t xorshift_state = 1;

void pandemonium_splitmix64_set_state(const uint64_t x)
{
    splitmix_state = x;
}

uint64_t pandemonium_splitmix64_next(void)
{
    uint64_t z = (splitmix_state += U64(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) * U64(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * U64(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

uint64_t pandemonium_splitmix64(const uint64_t x)
{
    uint64_t z = (x +      U64(0x9e3779b97f4a7c15));
    z = (z ^ (z >> 30)) *  U64(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) *  U64(0x94d049bb133111eb);
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
    return xorshift_state *  U64(0x2545F4914F6CDD1D);
}

// x must be nonzero
uint64_t pandemonium_xorshift64star(uint64_t x)
{
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * U64(0x2545F4914F6CDD1D);
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

int pandemonium_csprng_arr(void* buf, const size_t count, const size_t size)
{
    if (buf == NULL || count == 0 || size == 0)
        return 1;
    if (count > SIZE_MAX / size)
        return 1;

    const size_t total_bytes = count * size;
    size_t remaining_bytes = total_bytes;

    while (remaining_bytes > 0) {
        const ssize_t result = getrandom((uchar*)buf + total_bytes - remaining_bytes, remaining_bytes, 0);
        fprintf(stderr, "Random bytes written: %zd\n", result);
        if (result < 0) {
            if (errno == EINTR)
                continue;   // interrupted by a signal before any bytes were read, just retry
            return 1;
        }
        assert((size_t)result <= remaining_bytes);
        remaining_bytes = remaining_bytes - (size_t)result;
    }
    return 0;
}

/*******************************************************/

int pandemonium_csprng_range(void* buf, const size_t count, const size_t size, const uint64_t max)
{
    if (buf == NULL || count == 0 || size == 0 || size > 8 || max == 0)
        return 1;
    if (count > SIZE_MAX / size)
        return 1;

    const size_t total_bytes = count * size;
    const int sig_bits = 64 - __builtin_clzll(max);
    const uint64_t mask = (sig_bits == 64) ? (UINT64_MAX) : ((1UL << sig_bits) - 1UL);

    void* random_bytes = malloc(total_bytes < 256 ? 256 : total_bytes);
    if (random_bytes == NULL)
        return 1;

    size_t buf_index = 0;
    while (buf_index < total_bytes) {
        const size_t chunk_size = (total_bytes - buf_index < 256) ? 256 : (total_bytes - buf_index);
        if (pandemonium_csprng_arr(random_bytes, chunk_size, 1))
            goto CLEANUP;

        for (size_t i = 0; (i + size) <= chunk_size; i += size) {
            uint64_t candidate = 0;
            memcpy(&candidate, (uchar*)random_bytes + i, size);
            candidate &= mask;

            if (candidate > max) continue;
            memcpy((uchar*)buf + buf_index, &candidate, size);
            buf_index += size;
            if (!((buf_index + size) <= total_bytes))
                break;
        }
    }

    free(random_bytes);
    return 0;
CLEANUP:
    free(random_bytes);
    return 1;
}

/*******************************************************/

#define STATE_SIZE 16
#define ROUNDS 10
#define BLOCK_SIZE 64

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) do {                      \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = ROTL((b), 7);  \
} while(0)

static void chacha20_block(uint32_t* restrict x, const uint32_t* restrict const state)
{
    for (int i = 0; i < STATE_SIZE; ++i)
        x[i] = state[i];
    for (int i = 0; i < ROUNDS; ++i) {
        QR(x[0], x[4], x[8],  x[12]); QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]); QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < STATE_SIZE; ++i)
        x[i] += state[i];
}

void pandemonium_chacha20(Chacha20_ctx* restrict ctx, void* restrict out, const size_t out_size)
{
    assert(ctx != NULL);
    assert(out != NULL);

    if (ctx == NULL || out == NULL || out_size == 0) return;

    uint32_t state[STATE_SIZE] = {
        [0]  = 0x61707865,   [1]  = 0x3320646e,    [2]  = 0x79622d32,    [3]  = 0x6b206574,
        [4]  = ctx->key[0],  [5]  = ctx->key[1],   [6]  = ctx->key[2],   [7]  = ctx->key[3],
        [8]  = ctx->key[4],  [9]  = ctx->key[5],   [10] = ctx->key[6],   [11] = ctx->key[7],
        [12] = (uint32_t)(ctx->counter & UINT32_MAX), [13] = (uint32_t)(ctx->counter >> 32),
        [14] = (uint32_t)(ctx->nonce & UINT32_MAX),   [15] = (uint32_t)(ctx->nonce >> 32)
    };

    uint32_t x[STATE_SIZE];
    for (size_t i = 0; i < out_size; i += BLOCK_SIZE) {
        chacha20_block(x, state);
        ++(ctx->counter);
        state[12] = (uint32_t)(ctx->counter & UINT32_MAX);
        state[13] = (uint32_t)(ctx->counter >> 32);
        memcpy((uint8_t*)out + i, x, BLOCK_SIZE <= (out_size - i) ? BLOCK_SIZE : (out_size - i));
    }
}

int pandemonium_chacha20_genseed(Chacha20_ctx* ctx)
{
    assert(ctx != NULL);
    return (32 != getrandom(ctx->key, 32, 0));
}

