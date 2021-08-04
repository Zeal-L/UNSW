#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    // create a pipe
    int *pipe_1 = malloc(sizeof(int) *3);
    pipe(pipe_1);

    int pipe_2[2];
    pipe(pipe_2);

    int pipe_3[2];
    pipe(pipe_3);


    posix_spawn_file_actions_t actions_1;
    posix_spawn_file_actions_init(&actions_1);
    posix_spawn_file_actions_addclose(&actions_1, pipe_1[0]);
    posix_spawn_file_actions_adddup2(&actions_1, pipe_1[1], 1);

    posix_spawn_file_actions_t actions_2;
    posix_spawn_file_actions_init(&actions_2);
    posix_spawn_file_actions_adddup2(&actions_2, pipe_1[0], 0);
    posix_spawn_file_actions_adddup2(&actions_2, pipe_2[1], 1);

    posix_spawn_file_actions_t actions_3;
    posix_spawn_file_actions_init(&actions_3);
    posix_spawn_file_actions_adddup2(&actions_3, pipe_2[0], 0);
    posix_spawn_file_actions_adddup2(&actions_3, pipe_3[1], 1);

    posix_spawn_file_actions_t actions_4;
    posix_spawn_file_actions_init(&actions_4);
    posix_spawn_file_actions_addclose(&actions_4, pipe_3[1]);
    posix_spawn_file_actions_adddup2(&actions_4, pipe_3[0], 0);


    // [0]是读端是output，[1]是写端是input
    extern char **environ;

    pid_t pid;
    char *argv_1[] = {"/bin/cat", "shuck.c", NULL};
    if (posix_spawn(&pid, "/bin/cat", &actions_1, NULL, argv_1, environ) != 0) {
        perror("spawn");
        return 1;
    }
    close(pipe_1[1]);   // 重点
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        return 1;
    }
    //! /////////////////////////////////////////////////////////////////////////////////////

    char *argv_2[] = {"/usr/bin/wc", "-l", NULL};
    pid_t pid_2;
    if (posix_spawn(&pid_2, "/usr/bin/wc", &actions_2, NULL, argv_2, environ) != 0) {
        perror("spawn");
        return 1;
    }
    close(pipe_2[1]);    // 重点
    int exit_status_2;
    if (waitpid(pid_2, &exit_status_2, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    //! /////////////////////////////////////////////////////////////////////////////////////

    char *argv_3[] = {"/usr/bin/wc", "-c", NULL};
    pid_t pid_3;
    if (posix_spawn(&pid_3, "/usr/bin/wc", &actions_3, NULL, argv_3, environ) != 0) {
        perror("spawn");
        return 1;
    }
    close(pipe_3[1]);   // 重点
    int exit_status_3;
    if (waitpid(pid_3, &exit_status_3, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    //! /////////////////////////////////////////////////////////////////////////////////////

    char *argv_4[] = {"/usr/bin/wc", "-c", NULL};
    pid_t pid_4;
    if (posix_spawn(&pid_4, "/usr/bin/wc", &actions_4, NULL, argv_4, environ) != 0) {
        perror("spawn");
        return 1;
    }

    int exit_status_4;
    if (waitpid(pid_4, &exit_status_4, 0) == -1) {
        perror("waitpid");
        return 1;
    }

    // free the list of file actions
    posix_spawn_file_actions_destroy(&actions_1);
    posix_spawn_file_actions_destroy(&actions_2);
    posix_spawn_file_actions_destroy(&actions_3);
    posix_spawn_file_actions_destroy(&actions_4);
    return 0;
}