// Print position of first non-ASCII byte in file

#include <stdio.h>
#include <stdlib.h>

void process_file(char *pathname);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        process_file(argv[arg]);
    }
    return 0;
}

void invalid(char *pathname, ssize_t utf8_count) {
    printf("%s: invalid UTF-8 after %zd valid UTF-8 characters\n",  pathname, utf8_count);
    exit(0);
}

int get_continuation_byte(FILE *stream, char *pathname, ssize_t utf8_count) {
    int byte = fgetc(stream);
    if (byte == EOF || (byte & 0xC0) != 0x80) {
        invalid(pathname,  utf8_count);
    }
    return byte;
}

void process_file(char *pathname) {
    FILE *stream = fopen(pathname, "r");
    if (stream == NULL) {
        perror(pathname);
        exit(1);
    }

    ssize_t utf8_count;
    int byte1;
    for (utf8_count = 0; (byte1 = fgetc(stream)) != EOF; utf8_count++) {
        if ((byte1 & 0x80) == 0x00) {
            continue;
        }

        get_continuation_byte(stream, pathname, utf8_count);

        if ((byte1 & 0xE0) == 0xC0) {
            continue;
        }

        get_continuation_byte(stream, pathname, utf8_count);

        if ((byte1 & 0xF0) == 0xE0) {
            continue;
        }

        get_continuation_byte(stream, pathname, utf8_count);

        if ((byte1 & 0xF8) == 0xF0) {
            continue;
        }

        invalid(pathname,  utf8_count);
    }

    fclose(stream);
    printf("%s: %zd UTF-8 characters\n",  pathname, utf8_count);
}