// Multiply a float by 2048 using bit operations only

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        union overlay input, result;

        input.f = atof(argv[arg]);
        result.u = float_2048(input.u);
        printf("%.9g\n", result.f);
    }

    return 0;
}
