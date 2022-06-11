#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
  printf("Oh noe; my code flow\n");
  system("/bin/sh");
}

void lose(void) { system("/usr/games/cowsay `/usr/games/fortune`"); }

void vuln() {
  void (*function)(void) = lose;
  char buffer[64];

  setbuf(stdout, NULL);
  printf("The winning function is at %p\n", win);
  printf("Do you remember how function pointers work ?\n");
  gets(&buffer);
  printf("Preparing to jump to %p\n", function);
  fflush(stdout);
  function();
}

int main(int argc, char **argv) { vuln(); }
