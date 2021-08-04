// simple example of catching a signal
// don't compile with dcc

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void report_signal(int signum) {
    printf("Signal %d received\n", signum);
    printf("Please send help\n");
    exit(0);
}


int main(int argc, char *argv[]) {
    struct sigaction action = {.sa_handler = report_signal};
    sigaction(SIGFPE, &action, NULL);

    // this will produce a divide by zero
    // if there are no command-line arguments
    // which will cause program to receive SIGFPE

    printf("%d\n", 42/(argc - 1));

    printf("Good bye\n");
}