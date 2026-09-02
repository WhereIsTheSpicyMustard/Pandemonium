#ifndef PANDEMONIUM_H
#define PANDEMONIUM_H

#include <stddef.h>
#include <stdint.h>

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
int       pandemonium_csprng_arr(void* buf, const size_t count, const size_t size);
int       pandemonium_csprng_range(void* buf, const size_t count, const size_t size, const uint64_t max);

#endif
