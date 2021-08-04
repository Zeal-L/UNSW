#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {

    char *path = getenv(argv[argc-1]);
    int num = (path && strlen(path)) ? 1 : 0;
    printf("%d\n", num);

    return 0;
}

