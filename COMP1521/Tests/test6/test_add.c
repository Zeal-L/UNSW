#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "add.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <d> <s> <t>\n", argv[0]);
        return 1;
    }
    int d = strtol(argv[1], NULL, 0);
    int s = strtol(argv[2], NULL, 0);
    int t = strtol(argv[3], NULL, 0);
    uint32_t result = make_add(d, s, t);
    printf("make_add(%d, %d, %d) returned 0x%08x\n", d, s, t, result);
    return 0;
}
