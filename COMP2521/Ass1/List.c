
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "List.h"
#include "Record.h"

#define DEFAULT_MAX_ITEMS 64

struct list {
    Record *items;
    int     numItems;
    int     maxItems;
};

////////////////////////////////////////////////////////////////////////

// Creates a new empty list
List ListNew(void) {
    List l = malloc(sizeof(*l));
    if (l == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }

    l->numItems = 0;
    l->maxItems = DEFAULT_MAX_ITEMS;
    l->items = malloc(l->maxItems * sizeof(Record));
    return l;
}

// Frees the given list, but not the records contained in the list
void ListFree(List l) {
    free(l->items);
    free(l);
}

// Adds a record to the end of the list. Does NOT make a copy of the
// record before adding it to the list.
void ListAppend(List l, Record r) {
    if (l->numItems == l->maxItems) {
        l->items = realloc(l->items, 2 * l->maxItems * sizeof(Record));
        l->maxItems *= 2;
    }
    l->items[l->numItems] = r;
    l->numItems++;
}

// Returns the number of items in the list
int  ListSize(List l) {
    return l->numItems;
}

////////////////////////////////////////////////////////////////////////

struct listIterator {
    int  curr;
    List list;
};

// Creates an iterator for the given list
ListIterator ListItNew(List l) {
    ListIterator it = malloc(sizeof(*it));
    if (it == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }

    it->curr = 0;
    it->list = l;
    return it;
}

// Gets the next item in the list. The item should not be modified.
Record ListItNext(ListIterator it) {
    if (it->curr == it->list->numItems) {
        fprintf(stderr, "No more items in iterator!\n");
        exit(EXIT_FAILURE);
    }

    Record item = it->list->items[it->curr];
    it->curr++;
    return item;
}

// Checks if the list has a next item
bool ListItHasNext(ListIterator it) {
    return it->curr < it->list->numItems;
}

// Frees the given iterator
void ListItFree(ListIterator it) {
    free(it);
}

