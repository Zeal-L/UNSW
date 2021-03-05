// Implementation of the Queue ADT using an array

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Queue.h"

#define DEFAULT_SIZE 16 // DO NOT change this line

struct queue {
	Item *items;
	int size;
	int capacity;
};

static void increaseCapacity(Queue q);

/**
 * Creates a new empty queue
 */
Queue QueueNew(void) {
	Queue q = malloc(sizeof(*q));
	if (q == NULL) {
		fprintf(stderr, "couldn't allocate Queue\n");
		exit(EXIT_FAILURE);
	}
	
	q->items = malloc(DEFAULT_SIZE * sizeof(Item));
	if (q->items == NULL) {
		fprintf(stderr, "couldn't allocate Queue\n");
		exit(EXIT_FAILURE);
	}
	
	q->size = 0;
	q->capacity = DEFAULT_SIZE;
	return q;
}

/**
 * Frees all resources associated with the given queue
 */
void QueueFree(Queue q) {
	free(q->items);
	free(q);
}

/**
 * Adds an item to the end of the queue
 */
void QueueEnqueue(Queue q, Item it) {
	if (q->size == q->capacity) {
		increaseCapacity(q);
	}
	
	q->items[q->size++] = it;
}

/**
 * Doubles the capacity of the queue
 */
static void increaseCapacity(Queue q) {
	q->capacity *= 2;
	q->items = realloc(q->items, q->capacity * sizeof(Item));
	if (q->items == NULL) {
		fprintf(stderr, "couldn't resize Queue\n");
		exit(EXIT_FAILURE);
	}
}

/**
 * Removes an item from the front of the queue and returns it
 * Assumes that the queue is not empty
 */
Item QueueDequeue(Queue q) {
	assert(q->size > 0);
	
	Item it = q->items[0];
	for (int i = 1; i < q->size; i++) {
		q->items[i - 1] = q->items[i];
	}
	q->size--;
	return it;
}

/**
 * Gets the item at the front of the queue without removing it
 * Assumes that the queue is not empty
 */
Item QueueFront(Queue q) {
	assert(q->size > 0);
	
	return q->items[0];
}

/**
 * Gets the size of the given queue
 */
int QueueSize(Queue q) {
	return q->size;
}

/**
 * Returns true if the queue is empty, and false otherwise
 */
bool QueueIsEmpty(Queue q) {
	return q->size == 0;
}

/**
 * Prints the queue to the given file with items space-separated
 */
void QueueDump(Queue q, FILE *fp) {
	for (int i = 0; i < q->size; i++) {
		fprintf(fp, "%d ", q->items[i]);
	}
	fprintf(fp, "\n");
}

