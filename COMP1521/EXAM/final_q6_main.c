// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 6

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void convert_hexdump_to_bytes (FILE *hexdump_input, FILE *byte_output);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 2) return EXIT_FAILURE;

	char *path = argv[1];

	FILE *file = fopen (path, "w+");
	if (!file) return EXIT_FAILURE;

	convert_hexdump_to_bytes (stdin, file);

	fclose (file);

	return EXIT_SUCCESS;
}
