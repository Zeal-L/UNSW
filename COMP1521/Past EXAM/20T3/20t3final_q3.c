// COMP1521 20T3 final exam


#include <stdio.h>
#include <stdlib.h>

int intenv(char *name) {
    char *value = getenv(name);
    return value ? atoi(value) : 42;
}

int main(int argc, char *argv[]) {

    int diff = intenv(argv[1]) - intenv(argv[2]);

    printf("%d\n", diff < 10 && diff > -10);

    return 0;
}
