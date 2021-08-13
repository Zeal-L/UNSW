#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main(int argc, char *argv[]) {
    assert(argc == 3);
    char *value1 = getenv(argv[1]);
    char *value2 = getenv(argv[2]);
    if (value1 != NULL && value2 != NULL && strcmp(value1, value2) == 0) {
        printf("1\n");
    } else {
        printf("0\n");
    }
    return 0;
}