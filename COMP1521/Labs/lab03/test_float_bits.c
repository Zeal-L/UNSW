// Extract the 3 parts of a float using bit operations only

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        union overlay input;

        input.f = atof(argv[arg]);
        float_components_t c = float_bits(input.u);

        printf("float_bits(%.9g) returned\n", input.f);
        printf("sign=0x%x\n", c.sign);
        printf("exponent=0x%02x\n", c.exponent);
        printf("fraction=0x%06x\n", c.fraction);

        printf("is_nan returned %d\n", is_nan(c));
        printf("is_positive_infinity returned %d\n", is_positive_infinity(c));
        printf("is_negative_infinity returned %d\n", is_negative_infinity(c));
        printf("is_zero returned %d\n", is_zero(c));
    }

    return 0;
}
