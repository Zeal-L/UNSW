// list.h - Interface to singly-linked list ADT

#ifndef LIST_H
#define LIST_H

#include <stdio.h>
#include <stdlib.h>

/* External view of List (item is of type int).

   To simplify this exam setup, we are exposing the
   following types to a client.
*/

typedef struct list *List;

typedef struct node *Node;

struct node {
    int value;
    Node next;
};

struct list {
    Node first;
    Node last;
};

// create an empty list
List newList(void);

// create a new list node
Node newNode(int val);

// free memory for a list
void dropList(List l);

// prints a list to the given file
void showList(FILE *out, List l);

// creates a list by reading integer values from a line
List getList(char *line);

#endif

