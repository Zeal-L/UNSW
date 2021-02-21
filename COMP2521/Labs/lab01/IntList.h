// IntList.h - Lists of integers (interface)
// Written by John Shepherd, July 2008

#ifndef INTLIST_H
#define INTLIST_H

#include <stdbool.h>
#include <stdio.h>

/**
 * External view of IntList ... implementation in IntList.c
 */
typedef struct IntListRep *IntList;

/**
 * Create a new, empty IntList.
 */
IntList newIntList(void);

/**
 * Release all resources associated with an IntList.
 */
void freeIntList(IntList);

/**
 * Create an IntList by reading values from a file.
 * Assume that the file is open for reading.
 */
IntList getIntList(FILE *);

/**
 * Display IntList as one integer per line on `stdout`.
 */
void showIntList(IntList);

/**
 * Append one integer to the end of an IntList.
 */
void IntListInsert(IntList, int);

/**
 * Insert an integer into correct place in a sorted IntList.
 */
void IntListInsertInOrder(IntList, int);

/**
 * Return number of elements in an IntList.
 */
int IntListLength(IntList);

/**
 * Make a copy of an IntList.
 * New list should look identical to the original list.
 */
IntList IntListCopy(IntList);

/**
 * Make a sorted copy of an IntList.
 */
IntList IntListSortedCopy(IntList);

/**
 * Check whether an IntList is sorted in ascending order.
 * Returns `false` if list is not sorted, `true` if it is.
 */
bool IntListIsSorted(IntList);

/**
 * Check internal consistency of an IntList.
 */
bool IntListOK(IntList);

/**
 * Display an IntList as one integer per line to a file.
 * Assume that the file is open for writing.
 */
void IntListPrint(FILE *, IntList);

#endif
