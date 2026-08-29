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
int       pandemonium_csprng_uint8_arr(uint8_t* buf, const size_t count);
int       pandemonium_csprng_uint16_arr(uint16_t* buf, const size_t count);
int       pandemonium_csprng_uint32_arr(uint32_t* buf, const size_t count);
int       pandemonium_csprng_uint64_arr(uint64_t* buf, const size_t count);
int       pandemonium_csprng_uint8_range(uint8_t* buf, const size_t count, const uint8_t max);
int       pandemonium_csprng_uint16_range(uint16_t* buf, const size_t count, const uint16_t max);
int       pandemonium_csprng_uint32_range(uint32_t* buf, const size_t count, const uint32_t max);
int       pandemonium_csprng_uint64_range(uint64_t* buf, const size_t count, const uint64_t max);

#endif
