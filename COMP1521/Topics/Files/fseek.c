// use fseek to access diferent bytes of a file with no error checking

// the return value of the calls to fopen, fseek and fgetc
// should be checked to see if they worked!

#include <stdio.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <source file>\n", argv[0]);
        return 1;
    }

    FILE *input_stream = fopen(argv[1], "rb");

    // move to a position 1 byte from end of file
    // then read 1 byte
    fseek(input_stream, -1, SEEK_END);
    printf("last byte of the file is 0x%02x\n", fgetc(input_stream));

    // move to a position 0 bytes from start of file
    // then read 1 byte
    fseek(input_stream, 0, SEEK_SET);
    printf("first byte of the file is 0x%02x\n", fgetc(input_stream));

    // move to a position 41 bytes from start of file
    // then read 1 byte
    fseek(input_stream, 41, SEEK_SET);
    printf("42nd byte of the file is 0x%02x\n", fgetc(input_stream));

    // move to a position 58 bytes from current position
    // then read 1 byte
    fseek(input_stream, 58, SEEK_CUR);
    printf("100th byte of the file is 0x%02x\n", fgetc(input_stream));

    return 0;
}