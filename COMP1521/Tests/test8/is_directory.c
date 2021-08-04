#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
// Write a C program, is_directory.c, which takes
// one argument a pathname.
// If the pathname exists and is a directory, it should print 1,
// otherwise it should print 0.

int main(int argc, char *argv[]) {
    struct stat st;
    if (stat(argv[1], &st) != 0) {
        printf("0\n");
        return 0;
    }
    printf(S_ISDIR(st.st_mode) ? "1\n" : "0\n");
    return 0;
}
