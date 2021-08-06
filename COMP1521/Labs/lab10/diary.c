#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>



int main(int argc, char *argv[]) {

    char *path = getenv("HOME");
    char final[BUFSIZ] = {0};
    strcpy(final, path);
    strcat(final, "/.diary");
    FILE *fp = fopen(final, "a+");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }
    for (int i = 1; argv[i]; i++) {
        fputs(argv[i], fp);
        fputs(" ", fp);
    }
    fputs("\n", fp);
    fclose(fp);

    return 0;
}

