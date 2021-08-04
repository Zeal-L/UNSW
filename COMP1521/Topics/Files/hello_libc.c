// hello world implemented with libc

#include <unistd.h>

int main(void) {
    char bytes[16] = "Hello, Andrew!\n";

    // write takes 3 arguments:
    //   1) file descriptor, 1 == stdout
    //   2) memory address of first byte to write
    //   3) number of bytes to write

    write(1, bytes, 15); // p   rints Hello, Andrew! on stdout

    return 0;
}