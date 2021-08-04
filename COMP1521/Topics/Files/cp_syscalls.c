#include <unistd.h>

int main(int argc, char *argv[]) {
    // cp <file1> <file2> with syscalls, no error handling!
    // system call number 2 == open, takes 3 arguments:
    //   1) address of zero-terminated string containing file pathname
    //   2) bitmap indicating whether to write, read, ... file
    //      0x41 == write to file creating if necessary
    //   3) permissions if file will be newly created
    //      0644 == readable to everyone, writeable by owner

    long read_file_descriptor = syscall(2, argv[1], 0, 0);
    long write_file_descriptor = syscall(2, argv[2], 0x41, 0644);

    while (1) {
        char bytes[4096];
        long bytes_read = syscall(0, read_file_descriptor, bytes, 4096);
        if (bytes_read <= 0) {
            break;
        }
        syscall(1, write_file_descriptor, bytes, bytes_read);
    }

    return 0;
}