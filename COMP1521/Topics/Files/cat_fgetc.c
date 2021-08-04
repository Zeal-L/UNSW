// copy stdin to stdout implemented with fgetc

#include <stdio.h>

int main(void) {
    // c can not be char (common bug)
    // fgetc returns 0..255 and EOF (usually -1)
    int c;

    // return  bytes from the stream (stdin) one at a time
    while ((c = fgetc(stdin)) != EOF) {
        fputc(c, stdout); // write the byte to standard output
    }

    return 0;
}