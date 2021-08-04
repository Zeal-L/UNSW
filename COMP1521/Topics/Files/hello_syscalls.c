// hello world implemented with a direct syscall
// lowerest level, three times speed
#include <unistd.h>

int main(void) {
    char bytes[16] = "Hello, World!\n";

    // argument 1 to syscall is  system call number, 1 == write
    // remaining arguments are specific to each system call

    // write system call takes 3 arguments:
    //   1) file descriptor, 1 == stdout
    //   2) memory address of first byte to write
    //   3) number of bytes to write

    syscall(1, 1, bytes, 15); // prints Hello, World! on stdout

    return 0;
}