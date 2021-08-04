// copy stdin to stdout implemented with fgets

#include <stdio.h>

int main(void) {
    // return  bytes from the stream (stdin) line at a time
    // BUFSIZ is defined in stdio.h - its an efficient value to use
    // but any value would work


    char line[BUFSIZ];
    while (fgets(line, sizeof line, stdin) != NULL) {
        fputs(line, stdout);
    }
    //
    // NOTE: fgets returns a null-terminated string
    //       in other words a 0 byte marks the end of the bytes read
    //
    // fgets can not be used to read bytes which are 0
    // fputs takes a null-terminated string
    // so fputs can not be used to write bytes which are 0
    // hence you can't use fget/fputs for binary data e.g. jpgs

    return 0;
}