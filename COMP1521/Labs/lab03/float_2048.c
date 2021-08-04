// Multiply a float by 2048 using bit operations only

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"



// float_2048 is given the bits of a float f as a uint32_t
// it uses bit operations and + to calculate f * 2048
// and returns the bits of this value as a uint32_t
//
// if the result is too large to be represented as a float +inf or -inf is returned
//
// if f is +0, -0, +inf or -inf, or Nan it is returned unchanged
//
// float_2048 assumes f is not a denormal number
//
uint32_t float_2048(uint32_t f) {
    float_components_t c = float_bits(f);
    if (is_nan(c) ||
        is_positive_infinity(c) ||
        is_negative_infinity(c) ||
        is_zero(c)) return f;

    c.exponent += 11;

    if (c.exponent > 0xff) {
        c.exponent = 0xff;
        c.fraction = 0;
    }

    return c.sign << 31 | c.exponent << 23 | c.fraction;
}


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