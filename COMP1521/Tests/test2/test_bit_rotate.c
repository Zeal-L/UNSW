#include "bit_rotate.h"

int main(int argc, char *argv[]) {
    assert(argc > 1);

    int n_rotations = atoi(argv[1]);

    for (int arg = 2; arg < argc; arg++) {
        uint32_t bits = strtol(argv[arg], NULL, 0);
        printf(
            "bit_rotate(%d, 0x%04x) returned 0x%04x\n",
            n_rotations, bits, bit_rotate(n_rotations, bits)
        );
    }

    return 0;
}
