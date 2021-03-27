// Interface to the Stack ADT

#ifndef STACK_H
#define STACK_H

#include <stdbool.h>
#include <stdio.h>

#include "Cell.h"

typedef Cell Item;

typedef struct stack *Stack;

/**
 * Creates a new empty stack
 * Complexity: O(1)
 */
Stack StackNew(void);

/**
 * Frees all resources associated with the given stack
 * Complexity: O(n)
 */
void StackFree(Stack s);

/**
 * Adds an item to the top of the stack
 * Complexity: O(1)
 */
void StackPush(Stack s, Item it);

/**
 * Removes an item from the top of the stack and returns it
 * Assumes that the stack is not empty
 * Complexity: O(1)
 */
Item StackPop(Stack s);

/**
 * Gets the item at the top of the stack without removing it
 * Assumes that the stack is not empty
 * Complexity: O(1)
 */
Item StackTop(Stack s);

/**
 * Gets the size of the given stack
 * Complexity: O(1)
 */
int StackSize(Stack s);

/**
 * Returns true if the stack is empty, and false otherwise
 * Complexity: O(1)
 */
bool StackIsEmpty(Stack s);

/**
 * Prints the stack to the given file with items space-separated
 * Complexity: O(n)
 */
void StackDump(Stack s, FILE *fp);

#endif

