// swap pairs of bits of a 64-bit value, using bitwise operators

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

uint64_t bit_swap(uint64_t value);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        uint64_t s = strtoul(argv[arg], NULL, 0);

        printf("bit_swap(0x%016lx) returned 0x%016lx\n", s, bit_swap(s));
    }

    return 0;
}
