// Linked list definition and interface to utility functions

// !!! DO NOT MODIFY THIS FILE !!!

#ifndef LIST_H
#define LIST_H

#include <stdio.h>
#include <stdlib.h>

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

// Creates a new empty list
List ListNew(void);

// Creates a new list node
Node newNode(int value);

// Frees all memory associated with the given list
void ListFree(List l);

// Prints a list to stdout
void ListShow(List l);

// Creates a list by reading integer values from a line 
List ListRead(char *line);

#endif

