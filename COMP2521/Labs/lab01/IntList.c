// IntList.c - Lists of integers
// Written by John Shepherd, July 2008

#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>

#include "IntList.h"

// data structures representing IntList
struct IntListNode {
	int data;
	struct IntListNode *next;  // pointer to next node
};

struct IntListRep {
	int size;                  // number of elements in the list
	struct IntListNode *first; // pointer to node containing first value
	struct IntListNode *last;  // pointer to node containing last value
};

/**
 * Create a new, empty IntList.
 */
IntList newIntList(void)
{
	struct IntListRep *L = malloc(sizeof(*L));
	if (L == NULL) err(EX_OSERR, "couldn't allocate IntList");
	L->size = 0;
	L->first = NULL;
	L->last = NULL;
	return L;
}

/**
 * Release all resources associated with an IntList.
 */
void freeIntList(IntList L)
{
	if (L == NULL) return;

	struct IntListNode *curr = L->first;
	while (curr != NULL) {
		struct IntListNode *temp = curr;
		curr = curr->next;
		free(temp);
	}
	free(L);
}

/**
 * Create an IntList by reading values from a file.
 * Assume that the file is open for reading.
 */
IntList getIntList(FILE *inf)
{
	IntList L = newIntList ();

	int v;
	while (fscanf(inf, "%d", &v) == 1)
		IntListInsert(L, v);

	return L;
}

/**
 * Display IntList as one integer per line on `stdout`.
 */
void showIntList(IntList L)
{
	IntListPrint(stdout, L);
}

/**
 * Create a new IntListNode with value v
 * (this function is local to this ADT)
 */
static struct IntListNode *newIntListNode(int v)
{
	struct IntListNode *n = malloc(sizeof(*n));
	if (n == NULL) err(EX_OSERR, "couldn't allocate IntList node");
	n->data = v;
	n->next = NULL;
	return n;
}

/**
 * Append one integer to the end of an IntList.
 */
void IntListInsert(IntList L, int v)
{
	assert(L != NULL);

	struct IntListNode *n = newIntListNode(v);
	if (L->first == NULL)
		L->first = L->last = n;
	else {
		L->last->next = n;
		L->last = n;
	}
	L->size++;
}


/**
 * Insert an integer into correct place in a sorted IntList.
 */
void IntListInsertInOrder(IntList L, int v)
{
	
	// Empty list case
	if (L->first == NULL) {
		IntListInsert(L, v); 
		return;
	}
	
	// Smallest value case
	if (v <= L->first->data) {
		struct IntListNode *temp = L->first;
		struct IntListNode *n = newIntListNode(v);
		L->first = n;
		n->next = temp;
		L->size++;
		return;
	}

	// Value somewhere in the middle case
	struct IntListNode *n = newIntListNode(v);
	struct IntListNode *curr = L->first;
	
	while (curr->next) {
		if (v >= curr->data && v < curr->next->data) {
			n->next = curr->next;
			curr->next = n;
			L->size++;
			return;
		} 
		curr = curr->next;
	}
	// Largest value case
	IntListInsert(L, v);
	
}

/**
 * Return the number of elements in an IntList.
 */
int IntListLength(IntList L)
{
	assert(L != NULL);
	return L->size;
}

/**
 * Make a copy of an IntList.
 * New list should look identical to the original list.
 */
IntList IntListCopy(IntList L)
{
	assert(L != NULL);
	struct IntListRep *Lnew = newIntList();
	for (struct IntListNode *curr = L->first;
			curr != NULL; curr = curr->next)
		IntListInsert(Lnew, curr->data);
	return Lnew;
}

/**
 * Make a sorted copy of an IntList.
 */
IntList IntListSortedCopy(IntList L)
{
	assert(L != NULL);
	struct IntListRep *Lnew = newIntList();
	for (struct IntListNode *curr = L->first;
			curr != NULL; curr = curr->next)
		IntListInsertInOrder(Lnew, curr->data);
	return Lnew;
}

/**
 * Check whether an IntList is sorted in ascending order.
 * Returns `false` if list is not sorted, `true` if it is.
 */
bool IntListIsSorted(IntList L)
{
	assert(L != NULL);

	// trivial cases, 0 or 1 items
	if (L->size < 2)
		return true;

	// scan list, looking for out-of-order pair
	for (struct IntListNode *curr = L->first;
			curr->next != NULL; curr = curr->next)
		if (curr->next->data < curr->data)
			return false;

	// nothing out-of-order, must be sorted
	return true;
}

/**
 * Check internal consistency of an IntList.
 */
bool IntListOK(IntList L)
{
	if (L == NULL)
		return true;

	if (L->size == 0)
		return (L->first == NULL && L->last == NULL);

	// scan to (but not past) last node
	struct IntListNode *p = L->first;
	int count = 1; // at least one node
	while (p->next != NULL) {
		count++;
		p = p->next;
	}

	return (count == L->size && p == L->last);
}

/**
 * Display an IntList as one integer per line to a file.
 * Assume that the file is open for writing.
 */
void IntListPrint(FILE *outf, IntList L)
{
	assert(L != NULL);
	for (struct IntListNode *curr = L->first;
			curr != NULL; curr = curr->next)
		fprintf(outf, "%d\n", curr->data);
}
