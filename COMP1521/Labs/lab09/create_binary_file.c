#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc, char *argv[]) {

    FILE *f = fopen(argv[1], "w");
    if (f == NULL) {
        perror(argv[1]);
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        fputc(atoi(argv[i]), f);
    }

    fclose(f);

    return 0;
}