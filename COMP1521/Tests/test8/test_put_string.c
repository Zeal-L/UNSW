#include <stdio.h>
#include <stdlib.h>

#include "put_string.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <string>\n", argv[0]);
        return 1;
    }
    printf("calling put_string(\"%s\"):\n", argv[1]);
    put_string(argv[1]);
    return 0;
}
