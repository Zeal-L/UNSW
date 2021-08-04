// COMP1521 19t3 ... types and definitions for lab 3 float exercises.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

/// We use `union overlay' to obtain the raw bits of a `float'-type
/// value, by storing the `float' in the `f' field and then using the
/// `u' field to obtain the bits.
union overlay {
    float f;
    uint32_t u;
};

/// A struct suitable for storing the three components of a `float'.
typedef struct float_components {
    uint32_t sign;
    uint32_t exponent;
    uint32_t fraction;
} float_components_t;

/// For the `float_bits' exercise:
float_components_t float_bits(uint32_t bits);
int is_nan(float_components_t f);
int is_positive_infinity(float_components_t f);
int is_negative_infinity(float_components_t f);
int is_zero(float_components_t f);

/// For the `float_2048' exercise:
uint32_t float_2048(uint32_t f);

/// For the `float_less' exercise:
uint32_t float_less(uint32_t bits1, uint32_t bits2);

/// For the `float_print' exercise:
void float_print(uint32_t f);
