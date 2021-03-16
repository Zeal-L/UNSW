
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "List.h"

#define DEFAULT_MAX_ITEMS 64

struct list {
    char **items;
    int    numItems;
    int    maxItems;
};

static char *myStrdup(char *s);
static int qsortStrcmp(const void *ptr1, const void *ptr2);

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
    l->items = malloc(l->maxItems * sizeof(char *));
    return l;
}

// Frees all memory allocated for the given list
void ListFree(List l) {
    for (int i = 0; i < l->numItems; i++) {
        free(l->items[i]);
    }
    free(l->items);
    free(l);
}

// Adds a string to the end of the list
void ListAppend(List l, char *s) {
    if (l->numItems == l->maxItems) {
        l->items = realloc(l->items, 2 * l->maxItems * sizeof(char *));
        l->maxItems *= 2;
    }
    l->items[l->numItems] = myStrdup(s);
    l->numItems++;
}

static char *myStrdup(char *s) {
    char *copy = malloc((strlen(s) + 1) * sizeof(char));
    if (copy == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }
    return strcpy(copy, s);
}

// Returns the number of items in the list
int  ListSize(List l) {
    return l->numItems;
}

// Sorts the list in ASCII order
void ListSort(List l) {
    qsort(l->items, l->numItems, sizeof(char *), qsortStrcmp);
}

static int qsortStrcmp(const void *ptr1, const void *ptr2) {
    char *s1 = *(char **)ptr1;
    char *s2 = *(char **)ptr2;
    return strcmp(s1, s2);
}

// Prints the list, one string per line
// If the strings themselves contain newlines, too bad
void ListPrint(List l) {
    for (int i = 0; i < l->numItems; i++) {
        printf("%s\n", l->items[i]);
    }
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
char *ListItNext(ListIterator it) {
    if (it->curr == it->list->numItems) {
        fprintf(stderr, "No more items in iterator!\n");
        exit(EXIT_FAILURE);
    }

    char *item = it->list->items[it->curr];
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

