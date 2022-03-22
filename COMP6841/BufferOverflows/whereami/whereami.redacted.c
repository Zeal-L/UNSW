#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
	printf("Oh noe; my code flow\n");

	printf("FLAG{THIS_IS_A_PLACEHOLDER}\n");
}
void lose(void) {
	system("/usr/games/cowsay `/usr/games/fortune`");
}

int main(int argc, char** argv) {
    // setup local variables
	void (*function)(void) = lose;
	char buffer[64];

    // Print hints
	printf("The winning function is at %p\n",win);
	printf("Do you remember how function pointers work ?\n");

    // get user input, save to buffer
	gets(&buffer);

    // jump to function
	printf("Preparing to jump to %p\n",function);
	fflush(stdout);
	function();

	return EXIT_SUCCESS;
}
