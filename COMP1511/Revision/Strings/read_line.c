// Zeal L (abc982210694@gmail.com)
// 2020-11-23 10:30:40
// Zid: z5325156
// 
// Read a line of input.


#include <stdio.h>

#define BUFFER_LENGTH 16

void read_line(int buffer_len, char *buffer);

int main(int argc, char *argv[]) {
    // Declare a buffer.  In this case, we're declaring and using a
    // 64-byte buffer, but this could be any length you like, and in
    // our tests you will be required to handle arrays of any length.
    char buffer[BUFFER_LENGTH] = {0};

    // Read in a line...
    read_line(BUFFER_LENGTH, buffer);

    // ... and print it out.  The `%s` format code prints a string.
    printf("<%s>\n", buffer);

    return 0;
}

// Reads a line of input into `buffer`, excluding the newline;
// then ensures that `buffer` is a null-terminated string.
void read_line(int buffer_len, char *buffer) {
    int temp = 0;
    if (buffer_len == 1) {
        buffer[0] = 0;
    } else {
        for (int i = 0; ((temp = getchar()) != 10) && (i+1 < buffer_len); i++) {
            buffer[i] = temp;
            buffer[i+1] = 0;
        }
    }
}
