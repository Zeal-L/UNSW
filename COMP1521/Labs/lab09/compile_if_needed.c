// compile .c files specified as command line arguments if needed
//
// if my_program.c is speicified as an argument
// /usr/local/bin/dcc my_program.c -o my_program
// will be executed unless my_program exists
// and my_program's modification time is more recent than my_program.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

void compile_if_needed(char *c_file);
int is_compile_needed(char *c_file, char *binary);
void compile(char *c_file, char *binary);
char *get_binary_name(char *c_file);

int main(int argc, char *argv[]) {
    for (int arg = 1; arg < argc; arg++) {
        compile_if_needed(argv[arg]);
    }
    return 0;
}


// compile a C file if needed
void compile_if_needed(char *c_file) {
    char *binary = get_binary_name(c_file);
    if (is_compile_needed(c_file, binary)) {
        compile(c_file, binary);
    } else {
        printf("%s does not need compiling\n", c_file);
    }
    free(binary);
}

// DO NOT CHANGE CODE ABOVE HERE



// test if we need to recompile a C file
// return 1 if binary does not exist
//  or modification time of C file more recent than binary
// return 0, otherwise
int is_compile_needed(char *c_file, char *binary) {
    struct stat a, b;
    return (stat(c_file, &a) || stat(binary, &b)) ?
        1 : a.st_atime < b.st_atime ? 0 : 1;
}

// DO NOT CHANGE CODE BELOW HERE

#define C_COMPILER "/usr/local/bin/dcc"

// compile a C file
void compile(char *c_file, char *binary) {
    pid_t pid;
    extern char **environ;
    char *cc_argv[] = {C_COMPILER, c_file, "-o", binary, NULL};

    // print compile command
    for (char **p = cc_argv; *p; p++) {
        printf("%s ", *p);
    }
    printf("\n");

    // run compile command
    if (posix_spawn(&pid, C_COMPILER, NULL, NULL, cc_argv, environ) != 0) {
        perror("spawn");
        exit(1);
    }

    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }

    if (exit_status != 0) {
        fprintf(stderr, "compile failed\n");
        exit(1);
    }
}


// give a string ending in .c
// return malloc-ed copy of string without .c

char *get_binary_name(char *c_file) {
    char *binary = strdup(c_file);
    if (binary == NULL) {
        perror("");
        exit(1);
    }

    // remove .c suffix
    char *last_dot = strrchr(binary, '.');
    if (last_dot == NULL || last_dot[1] != 'c' || last_dot[2] != '\0') {
        fprintf(stderr, "'%s' does not end in  .c\n", c_file);
        exit(1);
    }
    *last_dot = '\0';
    return binary;
}
