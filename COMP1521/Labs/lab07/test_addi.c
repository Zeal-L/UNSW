#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "addi.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <t> <s> <i>\n", argv[0]);
        return 1;
    }
    int t = strtol(argv[1], NULL, 0);
    int s = strtol(argv[2], NULL, 0);
    int i = strtol(argv[3], NULL, 0);
    uint32_t result = addi(t, s, i);
    printf("addi(%d, %d, %d) returned 0x%08x\n", t, s, i, result);
    return 0;
}
