#include <stdio.h>

int main(int argc, char **argv) {

	printf("Program name: %s\n", argv[0]);
	if (argc < 2) printf("There are no other arguments\n");
	if (argc > 1) {
		printf("There are %d arguments:\n", argc - 1);
		for (int i = 1; i < argc; i++) {
			printf("	Argument %d is \"%s\"\n", i, argv[i]);
		}
	}

	return 0;
}
