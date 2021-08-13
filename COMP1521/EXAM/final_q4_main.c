// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 4

#include <stdio.h>
#include <stdlib.h>

long mul (long a, long b);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 3) return EXIT_FAILURE;

	long a = strtol (argv[1], NULL, 10);
	long b = strtol (argv[2], NULL, 10);

	long x = mul (a, b);

	printf ("%ld * %ld = %ld\n", a, b, x);

	return EXIT_SUCCESS;
}
