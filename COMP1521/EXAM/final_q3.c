// COMP1521 21T2 ... final exam, question 3

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void
cp (char *path_from, char *path_to)
{

    FILE *read = fopen(path_from, "r");

    FILE *write = fopen(path_to, "w");

	char line[BUFSIZ];
    while (fgets(line, sizeof line, read) != NULL) {
        fputs(line, write);
    }
	fclose(read);
	fclose(write);
}

