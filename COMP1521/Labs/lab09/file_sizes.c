#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>


int main(int argc, char *argv[]) {
    long total = 0;
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "r");
        if (f == NULL) {
            perror(argv[i]);
            return 1;
        }
        struct stat s;
        if (stat(argv[i], &s) != 0) {
            perror(argv[i]);
            exit(1);
        }
        long size = s.st_size;

        printf("%s: %ld bytes\n", argv[i], size);
        fclose(f);
        total += size;
    }
    printf("Total: %ld bytes\n", total);
    return 0;
}