#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

int main(int argc, char *argv[]) {
    FILE *f = fopen(argv[1], "r");
    if (f == NULL) {
        perror(argv[1]);
        return 1;
    }

    FILE *f2 = fopen("temp", "w");
    if (f2 == NULL) {
        perror("temp");
        return 1;
    }

    int c = fgetc(f);
    while (c != EOF) {
        if (isascii(c)) fputc(c, f2);
        c = fgetc(f);
    }

    remove(argv[1]);
    rename("temp", argv[1]);
    fclose(f);
    fclose(f2);
    return 0;
}