// COMP1521 19t3 ... types and definitions for week 4 test exercises.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#ifndef FLOAT_EXP_H
#define FLOAT_EXP_H

#include <assert.h>

/// We use `union overlay' to obtain the raw bits of a `float'-type
/// value, by storing the `float' in the `f' field and then using the
/// `u' field to obtain the bits.
union overlay {
    float f;
    uint32_t u;
};

uint32_t float_exp(uint32_t f);

#endif
