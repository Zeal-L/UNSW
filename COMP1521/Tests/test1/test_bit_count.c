// count bits in a uint64_t

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

int bit_count(uint64_t value);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        uint64_t s = strtoul(argv[arg], NULL, 0);

        printf("bit_count(0x%016lx) returned %d\n", s, bit_count(s));
    }

    return 0;
}
