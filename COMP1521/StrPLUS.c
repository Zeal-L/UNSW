#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>

void sighandler(int signum) {
    printf("Signal %d received\n", signum);
    fprintf(stderr, "<error: Cannot access memory>");
    exit(1);
}

static char *StrPLUS (int num, ...);

int main(int argc, char* argv[]) {
    char *string1 = "Hello, ";
    char *string2 = "World!";
    char *s = StrPLUS(3, string1, string2, "'1'");

    printf("%s", s);
    free(s);
    return 0;
}


// Concatenate any number of strings in order,
// the first argument is the total number of strings.
// Remember to FREE the return after use.
// Includes safety checks for exception parameters
// as well as for non-string types and memory capacity.
// Time Complexity: O(n^2)
static char *StrPLUS (int num, ...) {
    // SIGSEGV 非法访问存储器，如访问不存在的内存单元。
    signal(SIGSEGV, sighandler);
    if (num <= 0) {
        fprintf(stderr, "StrPLUS: <error: Invalid First Argument>\n");
        exit(1);
    }

    va_list valist;
    va_start(valist, num); // 获取第一个参数的首地址

    int size = 0;
    for (int i = 0; i < num; i++) {
        size += strlen(va_arg(valist, char*));
    }

    va_start(valist, num); // 重新把参数地址的指针指向首地址
    char* result = malloc(size * sizeof(char) + 1);
    if (result == NULL) {
        perror("StrPLUS");
        exit(1);
    }
    strcpy(result, va_arg(valist, char*));

    for (int i = 1; i < num; i++) {
	    strcat(result, va_arg(valist, char*));
    }
    va_end(valist);

    return result;
}