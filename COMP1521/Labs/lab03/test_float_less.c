// Compare 2 floats using bit operations only

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "floats.h"

void do_test(char *s1, char *s2);

#undef main

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <float1> <float2>\n", argv[0]);
        return 1;
    }

    do_test(argv[1], argv[2]);
    do_test(argv[2], argv[1]);

    return 0;
}

void do_test(char *s1, char *s2) {
    union overlay f1, f2;
    f1.f = atof(s1);
    f2.f = atof(s2);
    int result = float_less(f1.u, f2.u);
    printf("float_less(%.9g, %.9g) returned %d which is ", f1.f, f2.f, result);

    // compare result to comparison done using floats
    if ((f1.f < f2.f) == result) {
        printf("correct\n");
    } else {
        printf("incorrect\n");
    }
}
