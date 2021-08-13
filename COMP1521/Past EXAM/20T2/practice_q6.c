// Print position of first non-ASCII byte in file

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void process_file(char *pathname);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        process_file(argv[arg]);
    }
    return 0;
}

void process_file(char *pathname) {
    FILE *stream = fopen(pathname, "r");
    if (stream == NULL) {
        perror(pathname);
        exit(1);
    }

    ssize_t ascii_count = 0;
    int byte;
    while ((byte = fgetc(stream)) != EOF) {
        if (isascii(byte)) {
            ascii_count++;
        }
    }

    fclose(stream);
    printf("%s contains %zd ASCII bytes\n",  pathname, ascii_count);
}