#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc, char *argv[]) {

    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        perror(argv[1]);
        return 1;
    }
    int c = fgetc(f);
    int i = 0;
    while (c != EOF) {
        if (!isascii(c)) {
            printf("%s: byte %d is non-ASCII\n", argv[1], i);
            return 0;
        }
        c = fgetc(f);
        i++;
    }
    printf("%s is all ASCII\n", argv[1]);
    fclose(f);

    return 0;
}