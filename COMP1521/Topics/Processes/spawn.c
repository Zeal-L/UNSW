#include <stdio.h>
#include <stdlib.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(void) {

    pid_t pid;
    char *path = "./dadjoke";
    char *argv[] = { path, "3", NULL };
    extern char **environ;

    // spawn path as a separate process
    int spawn_error = posix_spawn(
                        &pid,
                        path,
                        NULL,
                        NULL,
                        argv,
                        environ
    );
    if (spawn_error != 0) {
        perror("spawn");
        exit(1);
    }

    // wait for spawned processes to finish
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }

    printf("%s finished with exit code %d\n", path, WEXITSTATUS(exit_status));


    return EXIT_SUCCESS;
}

// print all environment variables
void printEnviron() {
    extern char **environ;

    for (int i = 0; environ[i] != NULL; i++) {
        printf("%s\n", environ[i]);
    }
}
