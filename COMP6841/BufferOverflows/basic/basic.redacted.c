#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void);
void doCheck(void);

int main(int argc, char** argv) {
	doCheck();
	return EXIT_SUCCESS;
}

void doCheck(void) {
    // turn off print buffering
        setbuf(stdout, NULL);
    // setup local variables
	char team = 'A';
	char name[32];

    // Print
	printf("Halt! Who goes there!\n");

    // get user input, save to array
	gets(&name);

    // jump to function
	printf("Let me see if you're on the list, %s...\n",name);
	if (team == 'B') {
		win();
	}

	return;
}

void win(void) {
	printf("We can leave this here, because it is never called.\n");
	printf("Our flag is safe.\n");

	printf("FLAG{THIS_IS_A_PLACEHOLDER}\n");
	return;
}
