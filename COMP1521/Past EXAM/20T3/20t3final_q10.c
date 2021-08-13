#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <spawn.h>
#include <signal.h>
#include <wait.h>
#include <assert.h>
#include <errno.h>


void execute_line(int argc, char **command_line_args, char *line);
void *srealloc(void *ptr, size_t size);
char *sstrdup(char *s);
void error(char *message);

int main(int argc, char *argv[]) {
    if (argc == 1) {
        argc++;
        argv[1] = "echo";        // match xargs which  defaults to `echo`
    }

    char line[65536] = {0};
    while (fgets(line, 65536, stdin) != NULL) {
        execute_line(argc - 1, argv + 1, line);
    }

    return 0;
}

void execute_line(int argc, char **command_line_args, char *line) {
    char *p = strchr(line, '\n');
    if (p) *p = '\0';

    char **args = srealloc(NULL, (argc + 1) * sizeof (char *));
    for (int a = 0; a < argc; a++) args[a] = command_line_args[a];

    int new_argc = argc  + 1;
    for (char *token = strtok(line, " "); token != NULL; token = strtok(NULL, " ")) {
        args[new_argc - 1] = sstrdup(token);
        new_argc++;
        args = srealloc(args, new_argc * sizeof (char *));
    }
    args[new_argc - 1] = NULL;

    // ignore interrupts so our child can deal with it.
    if (sigaction(SIGINT, &(struct sigaction){ .sa_handler=SIG_IGN }, NULL) == -1) {
        error("sigaction");
    }

    // call the new process with it's processed command line args
    pid_t pid;
    if (posix_spawnp(&pid, args[0], NULL, NULL, args, NULL) != 0) {
        perror(args[0]);
    }

    if (waitpid(pid, NULL, 0) == -1) {
        error("waitpid");
    }

    // child has finished handle interrupt again
    if (sigaction(SIGINT, &(struct sigaction){ .sa_handler=SIG_DFL }, NULL) == -1) {
        error("sigaction");
    }

    for (int a = argc; a < new_argc - 1; a++) {
        free(args[a]);
    }
    free(args);

}

void *srealloc(void *ptr, size_t size) {
    char *n = realloc(ptr, size);
    if (n == NULL) {
        error("realloc");
    }
    return n;
}

char *sstrdup(char *s) {
    char *n = strdup(s);
    if (n == NULL) {
        error("strdup");
    }
    return n;
}

void error(char *message) {
    perror(message);
    exit(1);
}