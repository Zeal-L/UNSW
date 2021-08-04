// silly program which creates a 1000-deep directory hierarchy
// andrewt@unsw.edu.au for COMP1521 lecture example

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <limits.h>
// rm -r

int main(void) {

    for (int i = 0; i < 1000;i++) {
        char dirname[256];
        snprintf(dirname, sizeof dirname, "d%d", i);

        if (mkdir(dirname, 0755) != 0) {
            perror(dirname);
            return 1;
        }

        if (chdir(dirname) != 0) {
            perror(dirname);
            return 1;
        }

        char pathname[1000000];
        if (getcwd(pathname, sizeof pathname) == NULL) {
            perror("getcwd");
            return 1;
        }
        printf("\nCurrent directory now: %s\n", pathname);
    }

    return 0;
}