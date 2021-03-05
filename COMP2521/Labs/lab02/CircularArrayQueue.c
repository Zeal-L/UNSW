// Implementation of the Queue ADT using a circular array

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Queue.h"

#define DEFAULT_SIZE 16 // DO NOT change this line

// DO NOT modify this struct
struct queue {
	Item *items;
	int size;
	int capacity;
	int frontIndex;
};

static void increaseCapacity(Queue q);

/**
 * Creates a new empty queue
 */
Queue QueueNew(void) {
	Queue q = malloc(sizeof(*q));
	if (q == NULL) {
		fprintf(stderr, "couldn't allocate Queue");
		exit(EXIT_FAILURE);
	}
	
	q->items = malloc(DEFAULT_SIZE * sizeof(Item));
	if (q->items == NULL) {
		fprintf(stderr, "couldn't allocate Queue");
		exit(EXIT_FAILURE);
	}
	
	q->size = 0;
	q->capacity = DEFAULT_SIZE;
	q->frontIndex = 0;
	return q;
}

/**
 * Frees all resources associated with the given queue
 */
void QueueFree(Queue q) {
	free(q->items);
	free(q);
}

static void increaseCapacity(Queue q) {
	q->capacity *= 2;
	q->items = realloc(q->items, q->capacity * sizeof(Item));
	for (int i = 0; i <= q->frontIndex; i++) {
		q->items[q->frontIndex + q->size + i] = q->items[i];
	}
}

/**
 * Adds an item to the end of the queue
 */
void QueueEnqueue(Queue q, Item it) {

	// Normal case
	if (q->size + q->frontIndex < q->capacity) {
		q->items[q->frontIndex + q->size++] = it;

	// circular to front case
	} else if (q->frontIndex + q->size - q->capacity < q->frontIndex) {
		q->items[q->frontIndex + q->size++ - q->capacity] = it;

	// FULL case
	} else {
		increaseCapacity(q);
		q->items[q->frontIndex + q->size++] = it;
	}
	
}

/**
 * Removes an item from the front of the queue and returns it
 * Assumes that the queue is not empty
 */
Item QueueDequeue(Queue q) {
	assert(q->size > 0);
	
	Item it = q->items[q->frontIndex++];
	if (q->frontIndex >= q->capacity)
		q->frontIndex = 0;
	q->size--;

	return it;
}

/**
 * Gets the item at the front of the queue without removing it
 * Assumes that the queue is not empty
 */
Item QueueFront(Queue q) {
	assert(q->size > 0);
	
	return q->items[q->frontIndex];
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
	for (int i = q->frontIndex, j = 0; j < q->size; i = (i + 1) % q->capacity, j++) {
		fprintf(fp, "%d ", q->items[i]);
	}
	fprintf(fp, "\n");
}

