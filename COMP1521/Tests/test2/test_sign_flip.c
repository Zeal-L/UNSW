#include "sign_flip.h"

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        union overlay input, result;

        input.f = atof(argv[arg]);
        result.u = sign_flip(input.u);
        printf("sign_flip(%.9g) returned %.9g\n", input.f, result.f);
    }

    return 0;
}
