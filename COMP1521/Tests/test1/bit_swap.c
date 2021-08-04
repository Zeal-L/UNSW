// swap pairs of bits of a 64-bit value, using bitwise operators

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

// return value with pairs of bits swapped
uint64_t bit_swap(uint64_t value) {

    // 0x5555555555555555
    // 0101010101010101010101010101010101010101010101010101010101010101
    // 0xAAAAAAAAAAAAAAAA
    // 1010101010101010101010101010101010101010101010101010101010101010


    return ((value >> 1) & 0x5555555555555555) |
        ((value << 1) & 0xAAAAAAAAAAAAAAAA);
}

