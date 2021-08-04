#ifndef SIGN_FLIP_H
#define SIGN_FLIP_H

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

uint32_t sign_flip(uint32_t f);

#endif
