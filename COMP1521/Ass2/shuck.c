////////////////////////////////////////////////////////////////////////
// COMP1521 21t2 -- Assignment 2 -- shuck, A Simple Shell
// <https://www.cse.unsw.edu.au/~cs1521/21T2/assignments/ass2/index.html>
//
// Written by YOUR-NAME-HERE (z5325156) on INSERT-DATE-HERE.
//
// 2021-07-12    v1.0    Team COMP1521 <cs1521@cse.unsw.edu.au>
// 2021-07-21    v1.1    Team COMP1521 <cs1521@cse.unsw.edu.au>
//     * Adjust qualifiers and attributes in provided code,
//       to make `dcc -Werror' happy.
//

#include <sys/types.h>

#include <sys/stat.h>
#include <sys/wait.h>

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// [[ TODO: put any extra `#include's here ]]
#include <spawn.h>
#include <stdarg.h>
#include <ctype.h>
#include <glob.h>

// [[ TODO: put any `#define's here ]]


//
// Interactive prompt:
//     The default prompt displayed in `interactive' mode --- when both
//     standard input and standard output are connected to a TTY device.
//
static const char *const INTERACTIVE_PROMPT = "shuck& ";

//
// Default path:
//     If no `$PATH' variable is set in Shuck's environment, we fall
//     back to these directories as the `$PATH'.
//
static const char *const DEFAULT_PATH = "/bin:/usr/bin";

//
// Default history shown:
//     The number of history items shown by default; overridden by the
//     first argument to the `history' builtin command.
//     Remove the `unused' marker once you have implemented history.
//
static const int DEFAULT_HISTORY_SHOWN __attribute__((unused)) = 10;

//
// Input line length:
//     The length of the longest line of input we can read.
//
static const size_t MAX_LINE_CHARS = 1024;

//
// Special characters:
//     Characters that `tokenize' will return as words by themselves.
//
static const char *const SPECIAL_CHARS = "!><|";

//
// Word separators:
//     Characters that `tokenize' will use to delimit words.
//
static const char *const WORD_SEPARATORS = " \t\r\n";

// [[ TODO: put any extra constants here ]]


// [[ TODO: put any type definitions (i.e., `typedef', `struct', etc.) here ]]


static void execute_command(char **argv, char **path, char **environment);
static void do_exit(char **words);
static int is_executable(char *pathname);
static char **tokenize(char *s, char *separators, char *special_chars);
static void free_tokens(char **tokens);

// [[ TODO: put any extra function prototypes here ]]

static void run_commands(char **argv, char **paths, char **environment, posix_spawn_file_actions_t *actions);
static char *strPlus (int num, ...);
static char *pathfinder(char *target, char **paths);
static void print_history(int num);
static void save_history(char **argv);
static void run_history(char **argv, char **paths, char **environment);
static int *write_and_read_pipe(char **argv, char **paths, char **environment, int *pipeEnd, int last);
static int inputOrOutput(char **argv, char **paths, char **environment, int file);
static char *change_words(char **argv);
static char **globbing(char **argv);
static int redirection_check(char *program);
static int valid_arguments(char **words);

int main (void)
{
    // Ensure `stdout' is line-buffered for autotesting.
    setlinebuf(stdout);

    // Environment variables are pointed to by `environ', an array of
    // strings terminated by a NULL value -- something like:
    //     { "VAR1=value", "VAR2=value", NULL }
    extern char **environ;

    // Grab the `PATH' environment variable for our path.
    // If it isn't set, use the default path defined above.
    char *pathp;
    if ((pathp = getenv("PATH")) == NULL) {
        pathp = (char *) DEFAULT_PATH;
    }
    char **path = tokenize(pathp, ":", "");

    // Should this shell be interactive?
    bool interactive = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);

    // Main loop: print prompt, read line, execute command
    while (1) {
        // If `stdout' is a terminal (i.e., we're an interactive shell),
        // print a prompt before reading a line of input.
        if (interactive) {
            fputs(INTERACTIVE_PROMPT, stdout);
            fflush(stdout);
        }

        char line[MAX_LINE_CHARS];
        if (fgets(line, MAX_LINE_CHARS, stdin) == NULL)
            break;

        // Tokenise and execute the input line.
        char **command_words =
            tokenize(line, (char *) WORD_SEPARATORS, (char *) SPECIAL_CHARS);
        execute_command(command_words, path, environ);
        free_tokens(command_words);
    }

    free_tokens(path);
    return 0;
}


//
// Execute a command, and wait until it finishes.
//
//  * `words': a NULL-terminated array of words from the input command line
//  * `path': a NULL-terminated array of directories to search in;
//  * `environment': a NULL-terminated array of environment variables.
//
static void execute_command(char **words, char **path, char **environment)
{
    assert(words != NULL);
    assert(path != NULL);
    assert(environment != NULL);

    char *program = words[0];

    if (program == NULL) return; // nothing to do

    if (strcmp(program, "exit") == 0) {
        do_exit(words);
        // `do_exit' will only return if there was an error.
        return;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // [[ TODO: subset 5 ]]
    // Pipes
    int check = 0;  // If a '|' appears, check++
    for (int i = 0; words[i]; i++) if (words[i][0] == '|') check++;
    if (check != 0) {
        // Let's save the original command history.
        save_history(words);
        // First run
        int num = 0;    // number of words before '|'
        while (1) {
            if (words[num][0] == '|') break;
            num++;
        }
        char **argv_1 = calloc(num + 1, sizeof (*argv_1));
        for (int i = 0; i < num; i++) {
            argv_1[i] = calloc(strlen(words[i]) + 1, sizeof(char));
            strcpy(argv_1[i], words[i]);
        }
        int *pipeEnd = NULL;
        pipeEnd = write_and_read_pipe(argv_1, path, environment, pipeEnd, 0);
        if (pipeEnd == NULL) return;
        free_tokens(argv_1);

        // Remaining runs
        int index = num + 1;
        while (check != 0) {
            num = 0;
            while (words[index + num]) {
                if (words[index + num][0] == '|') break;
                num++;
            }
            char **argv = calloc(num + 2, sizeof (*argv));
            for (int i = 0; i < num; i++) {
                argv[i] = calloc(strlen(words[index + i]) + 1, sizeof(char));
                strcpy(argv[i], words[index + i]);
            }
            //                                        Is it the last command  ↓↓↓
            pipeEnd = write_and_read_pipe(argv, path, environment, pipeEnd, check == 1 ? 1 : 0);
            if (pipeEnd == NULL) return;
            free_tokens(argv);
            index += num + 1;
            check--;
        }
        free(pipeEnd);
        return;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // [[ TODO: subset 4 ]]
    // Input/Output Redirection
    int sign1 = 0;  // '<'
    int sign2 = 0;  // '>'
    for (int i = 0; words[i]; i++) {
        if (words[i][0] == '<') sign1++;
        else if (words[i][0] == '>') sign2++;
    }
    if (sign1 != 0 || sign2 != 0) {
        // Let's save the original command history.
        save_history(words);
        if (sign1 == 1 && sign2 != 0) { // '<' and '>' case
            inputOrOutput(words, path, environment, 2);
        } else if (sign1 == 1) {        // '<' case
            inputOrOutput(words, path, environment, 1);
        } else if (sign2 != 0) {    // '>' case
            inputOrOutput(words, path, environment, 0);
        }
        return;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // [[ TODO: subset 0 ]]
    // cd and pwd
    if (!strcmp(program, "cd")) {
        if (chdir(words[1] != NULL ? words[1] : getenv("HOME"))) {
            fprintf(stderr, "cd: %s: No such file or directory\n", words[1]);
        }
        save_history(words);
        return;
    }
    if (!strcmp(program, "pwd")) {
        if (words[1] != NULL) {
            fprintf(stderr, "%s: too many arguments\n", program);
            return;
        }
        printf("current directory is '%s'\n", getcwd(NULL, 0));
        save_history(words);
        return;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // [[ TODO: subset 2 ]]
    // Making history
    if (!strcmp(program, "history")) {
        if (valid_arguments(words)) {
            save_history(words);
            return;
        }
        print_history(words[1] != NULL ? atoi(words[1]) : 10);
        save_history(words);
        return;
    } else if (words[0][0] == '!') {
        if (valid_arguments(words)) return;
        run_history(words, path, environment);
        return;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // [[ TODO: subset 1 ]]
    run_commands(words, path, environment, NULL);
}

// Check if the arguments following the 'history' and '!' command is legal
static int valid_arguments(char **words) {
    if (words[1]) {
        if (words[2] != NULL) {
            fprintf(stderr, "%s: too many arguments\n", words[0]);
            return 1;
        }
        if (!(strspn(words[1], "0123456789") == strlen(words[1]))) {
            fprintf(stderr, "%s: %s: numeric argument required\n", words[0], words[1]);
            return 1;
        }
    }
    return 0;
}

// if a builtin command is specified with I/O redirection then return 1
static int redirection_check(char *program) {
    if (!strcmp(program, "history") ||
        !strcmp(program, "cd") ||
        !strcmp(program, "pwd")) {
        fprintf(stderr, "%s: I/O redirection not permitted for builtin commands\n", program);
        return 1;
    }
    return 0;
}

// remove '<' and move exe to [0]
// and return the filename
// example: "< shuck.c cat" -> "cat"
// example: "< j.txt grep 4" -> "grep 4"
static char *change_words(char **argv) {
    int num = 0;
    for (int i = 0; argv[i]; i++) num++;
    free(argv[0]);         // remove '<'
    char *file = malloc(sizeof(char) * strlen(argv[1]) + 1);
    strcpy(file, argv[1]);
    free(argv[1]);
    argv[0] = argv[2];    // move exe to first
    if (num == 3) {
        argv[1] = NULL;
    } else if (num == 4) {
        argv[1] = argv[3];
        argv[2] = NULL;
    } else if (num == 5) {
        argv[1] = argv[3];
        argv[2] = argv[4];
        argv[3] = NULL;
    }
    return file;
}

// 0 = Captures the output of spawned process
// 1 = sending info to spawned process
// 2 = do both
static int inputOrOutput(char **argv, char **paths, char **environment, int todo) {
    char *inputfile = malloc(sizeof(char) * BUFSIZ);
    char *outputfile = malloc(sizeof(char) * BUFSIZ);
    char sign[3] = {0};

    // create a pipe
    int curr_pipe[2];
    if (pipe(curr_pipe) == -1) {
        perror("pipe");
        exit(1);
    }
    int temp_pipe[2];
    if (pipe(temp_pipe) == -1) {
        perror("pipe");
        exit(1);
    }

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        perror("posix_spawn_file_actions_init");
        exit(1);
    }

    if (todo == 0) {
        if (posix_spawn_file_actions_addclose(&actions, curr_pipe[0]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[1], 1) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    } else if (todo == 1) {
        if (posix_spawn_file_actions_addclose(&actions, curr_pipe[1]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[0], 0) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    } else if (todo == 2) {
        if (posix_spawn_file_actions_addclose(&actions, temp_pipe[1]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, temp_pipe[0], 0) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
        if (posix_spawn_file_actions_addclose(&actions, curr_pipe[0]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[1], 1) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // sending info to spawned process
    if (todo == 1 || todo == 2) {
        strcpy(inputfile, argv[1]);
        free(argv[0]);
        free(argv[1]);
        int i = 0;
        for (; argv[i + 2]; i++) {
            argv[i] = argv[i + 2];
        }
        argv[i] = NULL;
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // Captures the output of spawned process
    if (todo == 0 || todo == 2) {
        // Calculate the sign, > or >>
        int sign2 = 0;  // '>'
        for (int i = 0; argv[i]; i++) if (argv[i][0] == '>') sign2++;
        if (sign2 == 1) { // '>' case
            sign[0] = 'w';
        } else if (sign2 == 2) {  // '>>' case
            sign[0] = 'a';
            sign[1] = '+';
        }

        // Calculate the final file name,
        // and delete everything including '>' and after
        int num = 1;
        for (int i = 0; !strspn(argv[i], "<>"); i++) num++;
        if (strspn(argv[num], ">")) num++;
        strcpy(outputfile, argv[num]);
        free(argv[num]);
        free(argv[num-1]);
        if (argv[num-2][0] == '>') {
            free(argv[num-2]);
            argv[num-2] = NULL;
        }
        argv[num-1] = NULL;
    }
    if (redirection_check(argv[0])) return 1;

    //? ////////////////////////////////////////////////////////////////////////////
    pid_t pid;
    char *path = pathfinder(argv[0], paths);
    if (!path || !is_executable(path)) {
        fprintf(stderr, "%s: command not found\n", argv[0]);
        return 1;
    }
    if (posix_spawn(&pid, path, &actions, NULL, argv, environment) != 0) {
        perror("spawn");
        exit(1);
    }

    close(temp_pipe[0]);
    if (todo == 1) close(curr_pipe[0]);
    else close(curr_pipe[1]);

    //? ////////////////////////////////////////////////////////////////////////////
    // If is read from the file / input
    if (todo == 1 || todo == 2) {
        FILE *f_write = fdopen(todo == 1 ? curr_pipe[1] : temp_pipe[1], "w");
        if (f_write == NULL) {
            perror("fdopen");
            exit(1);
        }
        FILE *target = fopen(inputfile, "r");
        if (target == NULL) {
            perror(inputfile);
            return 1;
        }
        char temp[BUFSIZ] = {0};
        while((fgets(temp, BUFSIZ, target)) != NULL){
            fprintf(f_write, "%s", temp);
        }
        fclose(f_write);
        fclose(target);
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // Entered into the file
    if (todo == 0 || todo == 2) {
        FILE *f_read = fdopen(curr_pipe[0], "r");
        if (f_read == NULL) {
            perror("fdopen");
            exit(1);
        }

        FILE *targetFile = fopen(outputfile, sign);
        if (targetFile == NULL) {
            perror(outputfile);
            return 1;
        }

        char temp[BUFSIZ] = {0};
        while((fgets(temp, BUFSIZ, f_read)) != NULL){
            fputs(temp, targetFile);
        }
        fclose(targetFile);
        fclose(f_read);
    }

    //? ////////////////////////////////////////////////////////////////////////////
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }
    printf("%s exit status = %d\n", path, WEXITSTATUS(exit_status));

    free(outputfile);
    free(inputfile);
    posix_spawn_file_actions_destroy(&actions);
    return 0;
}

// sending info to spawned process, and return the Output of it
static int *write_and_read_pipe(char **argv, char **paths, char **environment, int *pipeEnd, int last) {
    char filename[BUFSIZ] = {0};
    int check = 0;
    if (last) {
        for (int i = 0; argv[i]; i++) {
            if (argv[i][0] == '>') check++;
        }
        // Calculate the final file name,
        // and delete everything including '>' and after
        if (check) {
            int num = 1;
            while (!strspn(argv[num] , ">")) num++;
            if (argv[num+1][0] == '>') strcpy(filename, argv[num+2]);
            else strcpy(filename, argv[num+1]);
            free(argv[num]);
            free(argv[num+1]);
            if (num == 3 && argv[num+1][0] == '>') free(argv[num+2]);
            argv[num] = NULL;
        }
    }
    for (int i = 0; argv[i]; i++) if (argv[i][0] == '<') check++;
    if (pipeEnd == NULL && check) {
        char *temp = change_words(argv);
        strcpy(filename, temp);
        if (strspn(filename, "*?[~")) {
            glob_t matches;
            glob(filename, GLOB_NOCHECK|GLOB_TILDE, NULL, &matches);
            strcpy(filename, matches.gl_pathv[0]);
        }
        free(temp);
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // create a pipe
    int *curr_pipe = malloc(sizeof(int) * 3);
    if (pipe(curr_pipe) == -1) {
        perror("pipe");
        exit(1);
    }
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        perror("posix_spawn_file_actions_init");
        exit(1);
    }

    //? ////////////////////////////////////////////////////////////////////////////

    int temp_pipe[2];
    if (pipe(temp_pipe) == -1) {
        perror("pipe");
        exit(1);
    }
    // If the first one is read from the file
    if (pipeEnd == NULL && check) {
        if (posix_spawn_file_actions_addclose(&actions, temp_pipe[1]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, temp_pipe[0], 0) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
        if (posix_spawn_file_actions_addclose(&actions, curr_pipe[0]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[1], 1) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    // sending input to spawned process
    } else if (pipeEnd == NULL) {   // First time read output only
        if (posix_spawn_file_actions_addclose(&actions, curr_pipe[0]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[1], 1) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }

    } else if (last && filename[0] == 0) { // The last one connects directly to stdout
        if (posix_spawn_file_actions_addclose(&actions, pipeEnd[1]) != 0) {
            perror("posix_spawn_file_actions_init");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, pipeEnd[0], 0) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    } else {    // The last input to the file is processed in the same way
                //as the middle one, with both the write and read end open
        if (posix_spawn_file_actions_adddup2(&actions, pipeEnd[0], 0) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
        if (posix_spawn_file_actions_adddup2(&actions, curr_pipe[1], 1) != 0) {
            perror("posix_spawn_file_actions_adddup2");
            exit(1);
        }
    }

    //? ////////////////////////////////////////////////////////////////////////////
    pid_t pid;
    char *path = pathfinder(argv[0], paths);
    if (!path || !is_executable(path)) {
        fprintf(stderr, "%s: command not found\n", argv[0]);
        return NULL;
    }
    if (posix_spawn(&pid, path, &actions, NULL, argv, environment) != 0) {
        perror("spawn");
        exit(1);
    }

    close(temp_pipe[0]);
    close(curr_pipe[1]);


    //? ////////////////////////////////////////////////////////////////////////////
    // If the first one is read from the file
    if (pipeEnd == NULL && check) {
        FILE *f_write = fdopen(temp_pipe[1], "w");
        if (f_write == NULL) {
            perror("fdopen");
            exit(1);
        }
        FILE *target = fopen(filename, "r");
        if (target == NULL) {
            perror(filename);
            return NULL;
        }
        char temp[BUFSIZ] = {0};
        while((fgets(temp, BUFSIZ, target)) != NULL){
            fprintf(f_write, "%s", temp);
        }
        fclose(f_write);
        fclose(target);
    }

    //? ////////////////////////////////////////////////////////////////////////////
    // If the last one is entered into the file
    if (last && filename[0] != 0) {
        FILE *f_read = fdopen(curr_pipe[0], "r");
        if (f_read == NULL) {
            perror("fdopen");
            exit(1);
        }
        FILE *target = fopen(filename, check == 1 ? "w" : "a+");
        if (target == NULL) {
            perror(filename);
            return NULL;
        }
        char temp[BUFSIZ] = {0};
        while((fgets(temp, BUFSIZ, f_read)) != NULL){
            fprintf(target, "%s", temp);
        }
        fclose(f_read);
        fclose(target);
    }

    //? ////////////////////////////////////////////////////////////////////////////
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }
    if (last) printf("%s exit status = %d\n", path, WEXITSTATUS(exit_status));

    // free the list of file actions
    posix_spawn_file_actions_destroy(&actions);
    free(pipeEnd);
    free(path);
    return curr_pipe;
}

// Prints the nth command and then executes it,
// or, if n is not specified, the last command.
static void run_history(char **argv, char **paths, char **environment) {
    char *filePath = strPlus(2, getenv("HOME"), "/.shuck_history");
    FILE *history = fopen(filePath, "r");
    if (history == NULL) {
        perror(filePath);
        return;
    }
    free(filePath);

    // Locate the line number and read the entire line to temp
    char temp[BUFSIZ];
    if (argv[1]) {
        int num = atoi(argv[1]);
        for (int i = 0; i <= num; i++) {
            if (!fgets(temp, sizeof temp, history)) {
                fprintf(stderr,"!: invalid history reference\n");
                return;
            }
        }
    } else {  // If line number is not specified, the last command is executed
        while (fgets(temp, sizeof temp, history));
    }
    printf("%s", temp);

    char **command_words =
        tokenize(temp, (char *) WORD_SEPARATORS, (char *) SPECIAL_CHARS);
    run_commands(command_words, paths, environment, NULL);
    fclose(history);
}

// save given command run to the file $HOME/.shuck_history
static void save_history(char **argv) {
    char *filePath = strPlus(2, getenv("HOME"), "/.shuck_history");
    FILE *history = fopen(filePath, "a+");
    if (history == NULL) {
        perror(filePath);
        return;
    }
    free(filePath);
    if (history == NULL) {
        perror(".shuck_history");
        exit(1);
    }
    for (int i = 0; argv[i]; i++) {
        fprintf(history, "%s", argv[i]);
        if (argv[i+1]) fprintf(history, " ");
        else fprintf(history, "\n");
    }
    fclose(history);
}

// Prints the last n commands, or, if n is not specified, 10
static void print_history(int num) {
    char *filePath = strPlus(2, getenv("HOME"), "/.shuck_history");
    FILE *history = fopen(filePath, "r");
    if (history == NULL) {
        perror(filePath);
        return;
    }
    free(filePath);

    // Used to calculate line numbers
    int numLine = 0;
    char temp[BUFSIZ];
    while (fgets(temp, sizeof temp, history)) {
        numLine++;
    }

    int headCheck = 1;
    int numBack = 0;
    // Pointer to the last char of the file
    fseek(history, -2, SEEK_END);
    for (int i = 0; i < num; i++) {
        numBack++;
        while(fgetc(history) != '\n') {
            if (fseek(history, -2, SEEK_CUR)) {
                // In case the file pointer exceeds the file header
                fseek(history, -1, SEEK_CUR);
                break;
            }
        }
        char line[BUFSIZ];
        fgets(line, sizeof line, history);
        if (fseek(history, -(strlen(line) + 2), SEEK_CUR)) {
            // In case the file pointer exceeds the file header
            fseek(history, -(strlen(line)), SEEK_CUR);
            headCheck = 0;
            break;
        }
    }
    if (headCheck) fseek(history, 2, SEEK_CUR);

    for (int i = 0; i < num; i++) {
        char line[BUFSIZ];
        if (!fgets(line, sizeof line, history)) break;
        printf("%d: %s", numLine + i - numBack, line);
    }
    fclose(history);
}

// Find the path where the target exists
static char *pathfinder(char *target, char **paths) {
	for (int i = 0; paths[i]; i++) {
		char *copy = strPlus(3, paths[i], "/", target);
		if (is_executable(copy)) return copy;
		free(copy);
	}
    return NULL;
}

// [[ TODO: subset 3 ]]
// If any of the characters '*', '?', '[', or '~' appear in a word,
// that word should be taken as a pattern, and should be replaced by all
// of the words matching that pattern using the glob library function
static char **globbing(char **argv) {
    glob_t matches;
    char *temp1 = NULL;
    for (int i = 1; argv[i]; i++) {
        int result = glob(argv[i], GLOB_NOCHECK|GLOB_TILDE, NULL, &matches);
        if (result != 0) {
            perror("glob");
            exit(1);
        } else {
            if (i == 1) temp1 = strPlus(4, argv[0], " ", matches.gl_pathv[0], " ");
            else temp1 = strPlus(3, temp1, matches.gl_pathv[0], " ");
            for (size_t j = 1; j < matches.gl_pathc; j++) {
                char *temp2 = malloc(sizeof(char) * BUFSIZ);
                strcpy(temp2, temp1);
                free(temp1);
                temp1 = strPlus(3, temp2, matches.gl_pathv[j], " ");
                free(temp2);
            }
        }
    }
    char **newArgv = tokenize(temp1, (char *) WORD_SEPARATORS, (char *) SPECIAL_CHARS);
    free(temp1);
    return newArgv;
}

// Executive the given command in 'argv'
static void run_commands(char **argv, char **paths, char **environment, posix_spawn_file_actions_t *actions) {

    char **original_argv = argv;
    // Filename Expansion (Globbing)
    if (argv[1] != NULL && strspn(argv[1], "*?[~")) argv = globbing(argv);

    pid_t pid;
    char *path = argv[0];
    // If a command contains a '/', you do not need
    // to search for it in the path directories
    if (argv[0][0] != '/' && argv[0][0] != '.') {
        path = pathfinder(argv[0], paths);
    }

    if (!path || !is_executable(path)) {
        fprintf(stderr, "%s: command not found\n", argv[0]);
        return;
    }

    // spawn path as a separate process
    if (posix_spawn(&pid, path, actions, NULL, argv, environment)) {
        perror("spawn");
        exit(1);
    }

    // wait for spawned processes to finish
    int exit_status;
    if (waitpid(pid, &exit_status, 0) == -1) {
        perror("waitpid");
        exit(1);
    }
    printf("%s exit status = %d\n", path, WEXITSTATUS(exit_status));
    if (path != argv[0]) free(path);
    if (argv != original_argv) {
        free_tokens(argv);
        argv = original_argv;
    }
    if (actions == NULL) save_history(argv);
}

// Concatenate any number of strings in order,
// the first argument is the total number of strings.
// Remember to FREE the return after use.
// Includes safety checks for exception
// parameters and memory capacity.
// Time Complexity: O(n^2)
static char *strPlus (int num, ...) {
    if (num <= 0) {
        fprintf(stderr, "strPlus: <error: Invalid First Argument>\n");
        exit(1);
    }

    va_list valist;
    va_start(valist, num);

    int size = 0;
    for (int i = 0; i < num; i++) {
        size += strlen(va_arg(valist, char*));
    }

    va_start(valist, num);
    char* result = malloc(size * sizeof(char) + 1);
    if (result == NULL) {
        perror("strPlus");
        exit(1);
    }
    strcpy(result, va_arg(valist, char*));

    for (int i = 1; i < num; i++) {
	    strcat(result, va_arg(valist, char*));
    }
    va_end(valist);

    return result;
}


//
// Implement the `exit' shell built-in, which exits the shell.
//
// Synopsis: exit [exit-status]
// Examples:
//     % exit
//     % exit 1
//
static void do_exit(char **words)
{
    assert(words != NULL);
    assert(strcmp(words[0], "exit") == 0);

    int exit_status = 0;

    if (words[1] != NULL && words[2] != NULL) {
        // { "exit", "word", "word", ... }
        fprintf(stderr, "exit: too many arguments\n");

    } else if (words[1] != NULL) {
        // { "exit", something, NULL }
        char *endptr;
        exit_status = (int) strtol(words[1], &endptr, 10);
        if (*endptr != '\0') {
            fprintf(stderr, "exit: %s: numeric argument required\n", words[1]);
        }
    }

    exit(exit_status);
}


//
// Check whether this process can execute a file.  This function will be
// useful while searching through the list of directories in the path to
// find an executable file.
//
static int is_executable(char *pathname)
{
    struct stat s;
    return
        // does the file exist?
        stat(pathname, &s) == 0 &&
        // is the file a regular file?
        S_ISREG(s.st_mode) &&
        // can we execute it?
        faccessat(AT_FDCWD, pathname, X_OK, AT_EACCESS) == 0;
}


//
// Split a string 's' into pieces by any one of a set of separators.
//
// Returns an array of strings, with the last element being `NULL'.
// The array itself, and the strings, are allocated with `malloc(3)';
// the provided `free_token' function can deallocate this.
//
static char **tokenize(char *s, char *separators, char *special_chars)
{
    size_t n_tokens = 0;

    // Allocate space for tokens.  We don't know how many tokens there
    // are yet --- pessimistically assume that every single character
    // will turn into a token.  (We fix this later.)
    char **tokens = calloc((strlen(s) + 1), sizeof *tokens);
    assert(tokens != NULL);

    while (*s != '\0') {
        // We are pointing at zero or more of any of the separators.
        // Skip all leading instances of the separators.
        s += strspn(s, separators);

        // Trailing separators after the last token mean that, at this
        // point, we are looking at the end of the string, so:
        if (*s == '\0') {
            break;
        }

        // Now, `s' points at one or more characters we want to keep.
        // The number of non-separator characters is the token length.
        size_t length = strcspn(s, separators);
        size_t length_without_specials = strcspn(s, special_chars);
        if (length_without_specials == 0) {
            length_without_specials = 1;
        }
        if (length_without_specials < length) {
            length = length_without_specials;
        }

        // Allocate a copy of the token.
        char *token = strndup(s, length);
        assert(token != NULL);
        s += length;

        // Add this token.
        tokens[n_tokens] = token;
        n_tokens++;
    }

    // Add the final `NULL'.
    tokens[n_tokens] = NULL;

    // Finally, shrink our array back down to the correct size.
    tokens = realloc(tokens, (n_tokens + 1) * sizeof *tokens);
    assert(tokens != NULL);

    return tokens;
}

//
// Free an array of strings as returned by `tokenize'.
//
static void free_tokens(char **tokens)
{
    for (int i = 0; tokens[i] != NULL; i++) {
        free(tokens[i]);
    }
    free(tokens);
}