#ifndef PANDEMONIUM_H
#define PANDEMONIUM_H

#include <stdint.h>
#include <stddef.h>

// These are non-secure psudo random number generators.
// Good enough for many applications where security is
// not a concern.
void      pandemonium_splitmix64_set_state(const uint64_t x);
uint64_t  pandemonium_splitmix64(void);
uint64_t  pandemonium_splitmix64_next(uint64_t x);
void      pandemonium_xorshift64star_set_state(const uint64_t x);
uint64_t  pandemonium_xorshift64star(void);
uint64_t  pandemonium_xorshift64star_next(uint64_t x);


// these are cryptrographically secure psudo random number
// generators that return a random value of the specified type.
// The _arr versions return an array of length count of csprn 
// of the specified type, allocated on the heap, thus they need
// to be freed manually by free()
uint8_t   pandemonium_csprng_uint8(void);
uint16_t  pandemonium_csprng_uint16(void);
uint32_t  pandemonium_csprng_uint32(void);
uint64_t  pandemonium_csprng_uint64(void);
uint8_t*  pandemonium_csprng_uint8_arr(const size_t count);
uint16_t* pandemonium_csprng_uint16_arr(const size_t count);
uint32_t* pandemonium_csprng_uint32_arr(const size_t count);
uint64_t* pandemonium_csprng_uint64_arr(const size_t count);


uint64_t  pandemonium_get_range(const uint64_t min, const uint64_t max); // returns a random int in [min, max), uses mod and therefore will contain mod bias
double    pandemonium_get_double(void); // returns a random double in [0,1)

#endif
