// mkpref.c ... generates values in the range 1..max in prefix order

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

static void gen(int, int);

int main(int argc, char *argv[])
{
	if (argc != 2) {
		errx(EX_USAGE, "usage: %s <max>\n", argv[0]);
	}
	
	int max = atoi(argv[1]);
	gen(1, max);
	return EXIT_SUCCESS;
}

// recursive function to produce prefix order
// should look familiar from e.g. binary search
static void gen(int lo, int hi)
{
	if (lo > hi) return;
	int mid = (lo + hi) / 2;
	printf("%d\n", mid);
	gen(lo, mid - 1);
	gen(mid + 1, hi);
}

