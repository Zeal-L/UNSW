// use lseek to access diferent bytes of a file with no error checking

// the return value of thecalls to open, lseek and read
// should be checked to see if they worked!

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <source file>\n", argv[0]);
        return 1;
    }

    int read_file_descriptor = open(argv[1], O_RDONLY);
    char bytes[1];
    // move to a position 1 byte from end of file
    // then read 1 byte
    lseek(read_file_descriptor, -1, SEEK_END);
    read(read_file_descriptor, bytes, 1);
    printf("last byte of the file is 0x%02x\n", bytes[0]);

    // move to a position 0 bytes from start of file
    // then read 1 byte
    lseek(read_file_descriptor, 0, SEEK_SET);
    read(read_file_descriptor, bytes, 1);
    printf("first byte of the file is 0x%02x\n", bytes[0]);

    // move to a position 41 bytes from start of file
    // then read 1 byte
    lseek(read_file_descriptor, 41, SEEK_SET);
    read(read_file_descriptor, bytes, 1);
    printf("42nd byte of the file is 0x%02x\n", bytes[0]);

    // move to a position 58 bytes from current position
    // then read 1 byte
    lseek(read_file_descriptor, 58, SEEK_CUR);
    read(read_file_descriptor, bytes, 1);
    printf("100th byte of the file is 0x%02x\n", bytes[0]);

    return 0;
}