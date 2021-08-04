// Compare 2 floats using bit operations only

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"

// float_less is given the bits of 2 floats bits1, bits2 as a uint32_t
// and returns 1 if bits1 < bits2, 0 otherwise
// 0 is return if bits1 or bits2 is Nan
// only bit operations and integer comparisons are used
uint32_t float_less(uint32_t bits1, uint32_t bits2) {

    float_components_t b1 = float_bits(bits1);
    float_components_t b2 = float_bits(bits2);

    if (is_nan(b1) || is_nan(b2)) return 0;
    if ((b1.sign == 0 && b2.sign == 0 && (bits1 << 1) < (bits2 << 1)) ||
        (b1.sign == 1 && b2.sign == 1 && (bits1 << 1) > (bits2 << 1)) ||
        (b1.sign > b2.sign)) return 1;
    return 0;
}




// separate out the 3 components of a float
float_components_t float_bits(uint32_t f) {

    float_components_t c;
    c.sign = (f >> 31) & 1;
    c.exponent = (f & 0x7f800000) >> 23;
    c.fraction = f & 0x7fffff;

    return c;
}

// given the 3 components of a float
// return 1 if it is NaN, 0 otherwise
int is_nan(float_components_t f) {
    return (f.exponent == 0xff && f.fraction != 0) ? 1 : 0;
}