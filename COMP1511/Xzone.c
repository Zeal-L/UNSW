#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h> // #include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <fcntl.h>
#include <wchar.h>
#include "stdarg.h"
#include "uthash.h"
// #include <err.h>
// #include <arpa/inet.h>


int main(int argc, char* argv[]) {

    int arr[10] = {[1 ... 5] = 5};
    printf("%d\n", 5[arr]);
    printf("%d\n", 9[arr]);

    return EXIT_SUCCESS;
}

