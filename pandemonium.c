#include "pandemonium.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <assert.h>
#include <errno.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) do {      \
(a) += (b); (d) ^= (a); (d) = ROTL((d), 16); \
(c) += (d); (b) ^= (c); (b) = ROTL((b), 12); \
(a) += (b); (d) ^= (a); (d) = ROTL((d),  8); \
(c) += (d); (b) ^= (c); (b) = ROTL((b),  7); \
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

// These functions don't check for null, that is by design.
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
        const ssize_t result = getrandom((unsigned char*)buf + total_bytes - remaining_bytes, remaining_bytes, 0);
        fprintf(stderr, "Random bytes written: %zd\n", result);
        if (result == -1) {
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
            memcpy(&candidate, (unsigned char*)random_bytes + i, size);
            candidate &= mask;

            if (candidate > max) continue;
            memcpy((unsigned char*)buf + buf_index, &candidate, size);
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
/* work in progress
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
*/

