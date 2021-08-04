// Swap bytes of a short

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

uint16_t short_swap(uint16_t value);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        uint16_t s = strtol(argv[arg], NULL, 0);

        printf("short_swap(0x%04x) returned 0x%04x\n", s, short_swap(s));
    }

    return 0;
}
