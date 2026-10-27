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
// CHACHA20
/*******************************************************/

#define CHACHA20_STATE_SIZE 16
#define CHACHA20_ROUNDS 10
#define CHACHA20_BLOCK_SIZE 64

#define CHACHA20_ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define CHACHA20_QR(a, b, c, d) do {                      \
    (a) += (b); (d) ^= (a); (d) = CHACHA20_ROTL((d), 16); \
    (c) += (d); (b) ^= (c); (b) = CHACHA20_ROTL((b), 12); \
    (a) += (b); (d) ^= (a); (d) = CHACHA20_ROTL((d), 8);  \
    (c) += (d); (b) ^= (c); (b) = CHACHA20_ROTL((b), 7);  \
} while(0)

static inline void chacha20_block(uint32_t x[static restrict CHACHA20_STATE_SIZE], const uint32_t state[static restrict CHACHA20_STATE_SIZE])
{
    for (int i = 0; i < CHACHA20_STATE_SIZE; ++i)
        x[i] = state[i];
    for (int i = 0; i < CHACHA20_ROUNDS; ++i) {
        CHACHA20_QR(x[0], x[4], x[8],  x[12]); CHACHA20_QR(x[1], x[5], x[9],  x[13]);
        CHACHA20_QR(x[2], x[6], x[10], x[14]); CHACHA20_QR(x[3], x[7], x[11], x[15]);
        CHACHA20_QR(x[0], x[5], x[10], x[15]); CHACHA20_QR(x[1], x[6], x[11], x[12]);
        CHACHA20_QR(x[2], x[7], x[8],  x[13]); CHACHA20_QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < CHACHA20_STATE_SIZE; ++i)
        x[i] += state[i];
}

void pandemonium_chacha20(Chacha20_ctx* restrict ctx, void* restrict out, const size_t out_size)
{
    if (ctx == NULL || out == NULL)
        return;

    uint32_t state[CHACHA20_STATE_SIZE] = {
        [0]  = 0x61707865,   [1]  = 0x3320646e,    [2]  = 0x79622d32,    [3]  = 0x6b206574,
        [4]  = ctx->key[0],  [5]  = ctx->key[1],   [6]  = ctx->key[2],   [7]  = ctx->key[3],
        [8]  = ctx->key[4],  [9]  = ctx->key[5],   [10] = ctx->key[6],   [11] = ctx->key[7],
        [12] = (uint32_t)(ctx->counter & UINT32_MAX), [13] = (uint32_t)(ctx->counter >> 32),
        [14] = (uint32_t)(ctx->nonce & UINT32_MAX),   [15] = (uint32_t)(ctx->nonce >> 32)
    };

    uint32_t x[CHACHA20_STATE_SIZE];
    for (size_t i = 0; i < out_size; i += CHACHA20_BLOCK_SIZE) {
        chacha20_block(x, state);
        ++(ctx->counter);
        state[12] = (uint32_t)(ctx->counter & UINT32_MAX);
        state[13] = (uint32_t)(ctx->counter >> 32);
        memcpy((uint8_t*)out + i, x, CHACHA20_BLOCK_SIZE <= (out_size - i) ? CHACHA20_BLOCK_SIZE : (out_size - i));
    }
}

int pandemonium_chacha20_genseed(Chacha20_ctx* ctx)
{
    if (ctx == NULL) return 1;
    return (32 != getrandom(ctx->key, 32, 0));
}

/*******************************************************/
// SHA-256
/*******************************************************/

#define SHA256_WORD_SIZE 32
#define SHA256_ROTR(x, n) ((x >> n) | (x << (SHA256_WORD_SIZE - n)))
#define SHA256_CH(x, y, z) ((x & y) ^ (~x & z))
#define SHA256_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_CSIG0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_CSIG1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x, 18) ^ (x >> 3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ (x >> 10))

static const uint32_t SHA256_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};


// block is an array of length 16
static void sha256_process_block(const uint32_t block[static restrict 16], uint32_t H[static restrict 8])
{
    uint32_t W[64]; // message schedule

    // init working variables
    uint32_t a = H[0]; uint32_t e = H[4];
    uint32_t b = H[1]; uint32_t f = H[5];
    uint32_t c = H[2]; uint32_t g = H[6];
    uint32_t d = H[3]; uint32_t h = H[7];

    for (int t = 0; t < 16; t++) // first 16 words
        W[t] = block[t];
    for (int t = 16; t < 64; t++) // compute remaining schedule
        W[t] = SHA256_SIG1(W[t-2]) + W[t-7] + SHA256_SIG0(W[t-15]) + W[t-16];

    for (int t = 0; t < 64; t++) {
        const uint32_t T1 = h + SHA256_CSIG1(e) + SHA256_CH(e, f, g) + SHA256_K[t] + W[t];
        const uint32_t T2 = SHA256_CSIG0(a) + SHA256_MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // update hash values
    H[0] = a + H[0]; H[4] = e + H[4];
    H[1] = b + H[1]; H[5] = f + H[5];
    H[2] = c + H[2]; H[6] = g + H[6];
    H[3] = d + H[3]; H[7] = h + H[7];
}

// assumes M has already been checked for NULL
// length is in bytes
static inline uint32_t* sha256_parse_message(const uint8_t* restrict M1, const size_t length, size_t* restrict new_length)
{
    *new_length = ((length + 8 + 64) / 64) * 64;

    // this is confusing but the size of M2 depends on the size of M1
    // since its a multiple of 64 bytes it will also be a multiple of 4 bytes (32 bits)
    uint32_t* M2 = calloc(*new_length, 1);
    if (M2 == NULL) return NULL;
    uint8_t* M2_bytes = (uint8_t*)M2;

    memcpy(M2_bytes, M1, length);

    M2_bytes[length] = 0x80; // append 1 bit

     // append length
    uint64_t bit_length = (uint64_t)length * 8;
    for (size_t i = 0; i < 8; i++) {
        M2_bytes[*new_length - 1 - i] =
        (uint8_t)(bit_length >> (i * 8));
    }

    for (size_t i = 0; i < *new_length; i += 4) {
        const uint32_t word =
        ((uint32_t)M2_bytes[i + 0] << 24) |
        ((uint32_t)M2_bytes[i + 1] << 16) |
        ((uint32_t)M2_bytes[i + 2] << 8 ) |
        ((uint32_t)M2_bytes[i + 3]      );
        M2[i / 4] = word;
    }

    return M2;
}

int pandemonium_sha256(const uint8_t* restrict buf, const size_t length, uint32_t H[static restrict 8])
{
    if (buf == NULL) return 1;

    size_t new_length;
    uint32_t* M = sha256_parse_message(buf, length, &new_length); // new_length is in bytes
    if (M == NULL) return 1;
    new_length /= 4; // get new_length in terms of number of words (4 bytes each)

    // init hash
    H[0] = 0x6a09e667; H[4] = 0x510e527f;
    H[1] = 0xbb67ae85; H[5] = 0x9b05688c;
    H[2] = 0x3c6ef372; H[6] = 0x1f83d9ab;
    H[3] = 0xa54ff53a; H[7] = 0x5be0cd19;

    for (size_t i = 0; i < new_length; i += 16)
        sha256_process_block(M + i, H);

    free(M);
    M = NULL;
    return 0;
}


