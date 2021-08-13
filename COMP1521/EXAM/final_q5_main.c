// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 5

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void print_utf8_count (FILE *file);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 2) return EXIT_FAILURE;

	char *path = argv[1];

	FILE *file = fopen (path, "r");
	if (!file) return EXIT_FAILURE;

	print_utf8_count (file);

	return EXIT_SUCCESS;
}
