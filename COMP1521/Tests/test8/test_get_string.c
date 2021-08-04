#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "get_string.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <stdio>\n", argv[0]);
        return 1;
    }
    int size = atoi(argv[1]);
    assert(size > 0 && size < 65536);
    char s[size];
    printf("calling get_string(s, %d, stdin):\n", size);
    get_string(s, size, stdin);
    printf("s now contains '%s'\n", s);
    return 0;
}
