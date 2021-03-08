// mkrand.c ... generates values in the range 1..max in random order

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>

int main(int argc, char *argv[])
{
	if (argc != 2 && argc != 3) {
		errx(EX_USAGE, "usage: %s <max> [seed]\n", argv[0]);
	}
	
	int max = atoi(argv[1]);
	
	if (argc == 2) {
		srand(time(NULL));
	} else {
		srand((unsigned int) atoi(argv[2]));
	}

	if (max < 1) {
		return EXIT_SUCCESS;
	}

	if (max > 1000000) {
		err(EX_USAGE, "max is too large");
	}

	// theoretically perfect shuffle
	int vals[max];
	for (int i = 0; i < max; i++) {
		vals[i] = i + 1;
		int j = rand() % (i + 1);
		
		int tmp = vals[i];
		vals[i] = vals[j];
		vals[j] = tmp;
	}
	
	for (int i = 0; i < max; i++) {
		printf("%d\n", vals[i]);
	}

	return EXIT_SUCCESS;
}

