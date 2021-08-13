// COMP1521 20T3 final exam Q2 testing code

// Calls the `final_q2' function with each of the command-line arguments.
// See the exam paper and `final_q2.c' file for a description of the question.

// Do not change this file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int final_q2(uint32_t value);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        uint32_t w = strtol(argv[arg], NULL, 0);

        printf("final_q2(0x%08x) returned %d\n", w, final_q2(w));
    }

    return 0;
}
