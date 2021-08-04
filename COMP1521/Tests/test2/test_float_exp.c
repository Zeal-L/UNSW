#include "float_exp.h"

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        union overlay input;
        input.f = atof(argv[arg]);
        uint32_t exp = float_exp(input.u);
        printf("float_exp(%.9g) returned 0x%02x\n", input.f, exp);
    }

    return 0;
}
