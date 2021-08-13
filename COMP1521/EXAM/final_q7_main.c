// // // // // // // // DO NOT CHANGE THIS FILE! // // // // // // // //
// COMP1521 21T2 ... final exam, question 7

#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void cp_directory (char *dir_from, char *dir_to);

#ifdef main
#undef main
#endif

int
main (int argc, char *argv[])
{
	if (argc != 3) return EXIT_FAILURE;

	char *dir_from = argv[1];
	char *dir_to   = argv[2];

	cp_directory (dir_from, dir_to);

	return EXIT_SUCCESS;
}
