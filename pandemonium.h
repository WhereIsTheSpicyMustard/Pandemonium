#ifndef PANDEMONIUM_H
#define PANDEMONIUM_H

#include <stddef.h>
#include <stdint.h>

typedef struct Chacha20_ctx {
    uint32_t key[8];
    uint64_t counter;
    uint64_t nonce;
} Chacha20_ctx;

void      pandemonium_splitmix64_set_state(const uint64_t x);
uint64_t  pandemonium_splitmix64_next(void);
uint64_t  pandemonium_splitmix64(const uint64_t x);
void      pandemonium_xorshift64star_set_state(const uint64_t x);
uint64_t  pandemonium_xorshift64star_next(void);
uint64_t  pandemonium_xorshift64star(uint64_t x);

int       pandemonium_csprng_uint8(uint8_t* buf);
int       pandemonium_csprng_uint16(uint16_t* buf);
int       pandemonium_csprng_uint32(uint32_t* buf);
int       pandemonium_csprng_uint64(uint64_t* buf);

/* Writes count elements of size bytes each
  into buf from getrandom.*/
int       pandemonium_csprng_arr(void* buf, const size_t count, const size_t size);

/* Writes count elements of size bytes each
  into buf from getrandom.  Uses rejection
  sampling to keep values in the range [0, max] */
int       pandemonium_csprng_range(void* buf, const size_t count, const size_t size, const uint64_t max);

/* Writes out_size bytes generated from the chacha20 stream cipher into out[out_size].
 * Pointers must not be NULL.
 * Pointers must not alias.
 * Set the key, nonce and counter before using this function.
 * You can use the same key but with a different nonce to get independant streams from the same key.
 * Key stream has a period of 64 * UINT64_MAX */
void pandemonium_chacha20(Chacha20_ctx* restrict ctx, void* restrict out, const size_t out_size);

// Returns 0 on success, writes random bytes into ctx.key
int pandemonium_chacha20_genseed(Chacha20_ctx* ctx);

// Writes the sha-256 hash of buf[length] into H[8].
int pandemonium_sha256(const uint8_t* restrict buf, const size_t length, uint32_t H[static restrict 8]);

// Writes the SHA-512 hash of buf[lenght] into H[8].
int pandemonium_sha512(const uint8_t* restrict buf, const size_t length, uint64_t H[static restrict 8]);

#endif
