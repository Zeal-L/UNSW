// Extract the 3 parts of a float using bit operations only

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"

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

// given the 3 components of a float
// return 1 if it is inf, 0 otherwise
int is_positive_infinity(float_components_t f) {
    return (f.exponent == 0xff && f.fraction == 0 && f.sign == 0) ? 1 : 0;
}

// given the 3 components of a float
// return 1 if it is -inf, 0 otherwise
int is_negative_infinity(float_components_t f) {
    return (f.exponent == 0xff && f.fraction == 0 && f.sign != 0) ? 1 : 0;
}

// given the 3 components of a float
// return 1 if it is 0 or -0, 0 otherwise
int is_zero(float_components_t f) {
    return (f.exponent == 0 && f.fraction == 0) ? 1 : 0;
}
