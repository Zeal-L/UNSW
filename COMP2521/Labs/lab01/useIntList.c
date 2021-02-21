// useIntList.c - testing IntList data type

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "IntList.h"

int main(int argc, char *argv[])
{
	bool verbose = (argc == 2 && strcmp(argv[1], "-v") == 0);

	IntList myList = getIntList(stdin);
	if (verbose) {
		printf("Original:\n");
		showIntList(myList);
	}
	
	assert(IntListOK(myList));

	IntList myOtherList = IntListSortedCopy(myList);

	if (verbose) printf("Sorted:\n");
	showIntList(myOtherList);

	assert(IntListOK(myOtherList));
	assert(IntListIsSorted(myOtherList));

	freeIntList(myList);
	freeIntList(myOtherList);
	return EXIT_SUCCESS;
}