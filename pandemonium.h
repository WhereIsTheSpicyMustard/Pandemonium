#ifndef PANDEMONIUM_H
#define PANDEMONIUM_H

#include <stdint.h>
#include <stddef.h>

uint8_t   pandemonium_get_uint8 (void);
uint16_t  pandemonium_get_uint16(void);
uint32_t  pandemonium_get_uint32(void);
uint64_t  pandemonium_get_uint64(void);

uint8_t*  pandemonium_get_uint8_arr (const size_t count);
uint16_t* pandemonium_get_uint16_arr(const size_t count);
uint32_t* pandemonium_get_uint32_arr(const size_t count);
uint64_t* pandemonium_get_uint64_arr(const size_t count);

double    pandemonium_get_double(void);

void      pandemonium_splitmix64_set_state(const uint64_t x);
uint64_t  pandemonium_splitmix64(void);
uint64_t  pandemonium_splitmix64_ex(const uint64_t x);

uint64_t  pandemonium_xorshift64star(void);
void      pandemonium_xorshift64star_set_state(const uint64_t x);


#endif
