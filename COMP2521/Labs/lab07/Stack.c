// Implementation of the Stack ADT using a linked list

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Stack.h"

typedef struct node *Node;
struct node {
    Item item;
    Node next;
};

struct stack {
    Node head;
    int  size;
};

static Node newNode(Item it);

/**
 * Creates a new empty stack
 * Complexity: O(1)
 */
Stack StackNew(void) {
    Stack s = malloc(sizeof(*s));
    if (s == NULL) {
        fprintf(stderr, "couldn't allocate Stack\n");
        exit(EXIT_FAILURE);
    }

    s->head = NULL;
    s->size = 0;
    return s;
}

/**
 * Frees all resources associated with the given stack
 * Complexity: O(n)
 */
void StackFree(Stack s) {
    Node curr = s->head;
    while (curr != NULL) {
        Node temp = curr;
        curr = curr->next;
        free(temp);
    }
    free(s);
}

/**
 * Adds an item to the top of the stack
 * Complexity: O(1)
 */
void StackPush(Stack s, Item it) {
    Node n = newNode(it);
    n->next = s->head;
    s->head = n;
    s->size++;
}

static Node newNode(Item it) {
    Node n = malloc(sizeof(*n));
    if (n == NULL) {
        fprintf(stderr, "couldn't allocate Node\n");
        exit(EXIT_FAILURE);
    }

    n->item = it;
    n->next = NULL;
    return n;
}

/**
 * Removes an item from the top of the stack and returns it
 * Assumes that the stack is not empty
 * Complexity: O(1)
 */
Item StackPop(Stack s) {
    assert(s->size > 0);

    Node oldHead = s->head;
    Item it = oldHead->item;
    s->head = oldHead->next;
    free(oldHead);
    s->size--;

    return it;
}

/**
 * Gets the item at the top of the stack without removing it
 * Assumes that the stack is not empty
 * Complexity: O(1)
 */
Item StackTop(Stack s) {
    assert(s->size > 0);

    return s->head->item;
}

/**
 * Gets the size of the given stack
 * Complexity: O(1)
 */
int StackSize(Stack s) {
    return s->size;
}

/**
 * Returns true if the stack is empty, and false otherwise
 * Complexity: O(1)
 */
bool StackIsEmpty(Stack s) {
    return s->size == 0;
}

/**
 * Prints the stack to the given file with items space-separated
 * Complexity: O(n)
 */
void StackDump(Stack s, FILE *fp) {
    for (Node curr = s->head; curr != NULL; curr = curr->next) {
        fprintf(fp, "(%d, %d) ", curr->item.row, curr->item.col);
    }
    fprintf(fp, "\n");
}
