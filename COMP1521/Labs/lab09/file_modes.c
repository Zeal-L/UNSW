#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

void stat_file(char *pathname);

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        stat_file(argv[i]);
    }
    return 0;
}

void stat_file(char *pathname) {
    struct stat s;
    if (stat(pathname, &s) != 0) {
        perror(pathname);
        exit(1);
    }
    printf(S_ISDIR(s.st_mode) ? "d" : "-");
    printf(S_IRUSR == (S_IRUSR & s.st_mode) ? "r" : "-");
    printf(S_IWUSR == (S_IWUSR & s.st_mode) ? "w" : "-");
    printf(S_IXUSR == (S_IXUSR & s.st_mode) ? "x" : "-");
    printf(S_IRGRP == (S_IRGRP & s.st_mode) ? "r" : "-");
    printf(S_IWGRP == (S_IWGRP & s.st_mode) ? "w" : "-");
    printf(S_IXGRP == (S_IXGRP & s.st_mode) ? "x" : "-");
    printf(S_IROTH == (S_IROTH & s.st_mode) ? "r" : "-");
    printf(S_IWOTH == (S_IWOTH & s.st_mode) ? "w" : "-");
    printf(S_IXOTH == (S_IXOTH & s.st_mode) ? "x" : "-");
    printf(" %s\n", pathname);
}