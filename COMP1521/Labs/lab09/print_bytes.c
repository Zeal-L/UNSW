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
        if (isprint(c)) printf("byte %4d: %3d 0x%02x '%c'\n", i, c, c, c);
        else printf("byte %4d: %3d 0x%02x\n", i, c, c);
        c = fgetc(f);
        i++;
    }

    fclose(f);

    return 0;
}