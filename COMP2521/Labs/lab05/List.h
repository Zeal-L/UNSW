// A List ADT for strings

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

typedef struct list *List;

// Creates a new empty list
// Complexity: O(1)
List ListNew(void);

// Frees all memory allocated for the given list
// Complexity: O(n)
void ListFree(List l);

// Adds a string to the end of the list. Makes a copy of the string
// before adding it to the list.
// Average complexity: O(1)
void ListAppend(List l, char *s);

// Returns the number of items in the list
// Complexity: O(1)
int  ListSize(List l);

// Sorts the list in ASCII order
// Average complexity: O(n log n)
void ListSort(List l);

////////////////////////////////////////////////////////////////////////
// Do NOT use these functions

typedef struct listIterator *ListIterator;

// Creates an iterator for the given list
// Complexity: O(1)
ListIterator ListItNew(List l);

// Gets the next item in the list. The item should not be modified.
// Complexity: O(1)
char *ListItNext(ListIterator it);

// Checks if the list has a next item
// Complexity: O(1)
bool ListItHasNext(ListIterator it);

// Frees the given iterator
// Complexity: O(1)
void ListItFree(ListIterator it);

#endif

