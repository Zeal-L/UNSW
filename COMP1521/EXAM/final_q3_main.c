// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 3

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void cp (char *path_from, char *path_to);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 3) return EXIT_FAILURE;

	char *path_from = argv[1];
	char *path_to   = argv[2];

	cp (path_from, path_to);

	return EXIT_SUCCESS;
}
