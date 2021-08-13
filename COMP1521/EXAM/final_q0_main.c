// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 0

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int count_leading_zeroes (uint32_t x);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 2) return EXIT_FAILURE;

	uint32_t input = strtoul (argv[1], NULL, 10);

	int leading_zeroes = count_leading_zeroes (input);
	printf ("%d\n", leading_zeroes);

	return EXIT_SUCCESS;
}
