// Interface to the Queue ADT

#ifndef QUEUE_H
#define QUEUE_H

#include <stdbool.h>
#include <stdio.h>

#include "Cell.h"

typedef Cell Item;

typedef struct queue *Queue;

/**
 * Creates a new empty queue
 * Complexity: O(1)
 */
Queue QueueNew(void);

/**
 * Frees all resources associated with the given queue
 * Complexity: O(n)
 */
void QueueFree(Queue q);

/**
 * Adds an item to the end of the queue
 * Complexity: O(1)
 */
void QueueEnqueue(Queue q, Item it);

/**
 * Removes an item from the front of the queue and returns it
 * Assumes that the queue is not empty
 * Complexity: O(1)
 */
Item QueueDequeue(Queue q);

/**
 * Gets the item at the front of the queue without removing it
 * Assumes that the queue is not empty
 * Complexity: O(1)
 */
Item QueueFront(Queue q);

/**
 * Gets the size of the given queue
 * Complexity: O(1)
 */
int QueueSize(Queue q);

/**
 * Returns true if the queue is empty, and false otherwise
 * Complexity: O(1)
 */
bool QueueIsEmpty(Queue q);

/**
 * Prints the queue to the given file with items space-separated
 * Complexity: O(n)
 */
void QueueDump(Queue q, FILE *fp);

#endif

