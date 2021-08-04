#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <sys/wait.h>

// simple example of setting an environment variable
int main(void) {

    // set environment variable STATUS
    setenv("STATUS", "great", 1);

    char *getenv_argv[] = {"./get_status", NULL};
    pid_t pid;
    extern char **environ;
    if (posix_spawn(
        &pid, "./get_status",
        NULL,
        NULL,
        getenv_argv, environ) != 0) {
        perror("spawn");
        exit(1);
    }
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }

    // exit with whatever status s exited with
    return exit_status;
}