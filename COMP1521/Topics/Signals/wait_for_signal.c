// simple example of catching a signal
// don't compile with dcc

#include <stdio.h>
#include <unistd.h>
#include <signal.h>

void signal_handler(int signum) {
    printf("signal number %d received\n", signum);
}

int main(void) {
    struct sigaction action = {.sa_handler = signal_handler};
    sigaction(SIGUSR1, &action, NULL);

    printf("I am process %d waiting for signal %d\n", getpid(), SIGUSR1);

    // suspend execution for 1 hour
    sleep(3600);
}

// kill -s USR1