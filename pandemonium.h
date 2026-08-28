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

int       pandemonium__csprng_uint8(uint8_t* buf);
int       pandemonium__csprng_uint16(uint16_t* buf);
int       pandemonium__csprng_uint32(uint32_t* buf);
int       pandemonium__csprng_uint64(uint64_t* buf);
int       pandemonium__csprng_uint8_arr(uint8_t* buf, const size_t count);
int       pandemonium__csprng_uint16_arr(uint16_t* buf, const size_t count);
int       pandemonium__csprng_uint32_arr(uint32_t* buf, const size_t count);
int       pandemonium__csprng_uint64_arr(uint64_t* buf, const size_t count);
int       pandemonium__csprng_double(double* out);

#endif
