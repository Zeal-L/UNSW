// randList.c - generate a list of random integers
// Written by John Shepherd, July 2008

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <time.h>

int main(int argc, char *argv[])
{
	if (! (argc == 2 || argc == 3))
		errx(EX_USAGE, "usage: %s <#values> [seed]", argv[0]);

	int max = atoi(argv[1]);
	if (max < 1)
		errx(EX_USAGE, "too few values: %d", max);

	if (max > 1000000)
		errx(EX_USAGE, "too many values: %d", max);

	if (argc == 3)
		srand((unsigned) atoi(argv[2]));
	else
		srand((unsigned) time(NULL));

	for (int i = 0; i < max; i++)
		printf("%d\n", 1 + rand() % (max * 10));

	return EXIT_SUCCESS;
}
