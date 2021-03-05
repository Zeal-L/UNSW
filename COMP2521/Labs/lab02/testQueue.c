
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Queue.h"

static void testQueue1(void);
static void testQueue2(void);
static void testQueue3(void);
static void testQueue4(void);

int main(void) {
	testQueue1();
	testQueue2();
	testQueue3();
	testQueue4();
	
	printf("All tests passed!\n");
}

// tests general enqueueing and dequeueing
static void testQueue1(void) {
	Queue q = QueueNew();
	
	// enqueue 1 to 10
	for (int i = 1; i <= 10; i++) {
		QueueEnqueue(q, i);
		assert(QueueSize(q) == i);
	}
	
	// dequeue 1 to 5
	for (int j = 1; j <= 5; j++) {
		assert(QueueFront(q) == j);
		assert(QueueDequeue(q) == j);
	}
	assert(QueueSize(q) == 5);
	
	// enqueue 11 to 20, dequeue 6 to 15
	for (int i = 11, j = 6; i <= 20; i++, j++) {
		QueueEnqueue(q, i);
		assert(QueueFront(q) == j);
		assert(QueueDequeue(q) == j);
	}
	assert(QueueSize(q) == 5);
	
	// dequeue 16 to 20
	for (int j = 16; j <= 20; j++) {
		assert(QueueFront(q) == j);
		assert(QueueDequeue(q) == j);
	}
	assert(QueueSize(q) == 0);
	assert(QueueIsEmpty(q));
	
	// enqueue a number
	QueueEnqueue(q, 21);
	assert(QueueFront(q) == 21);
	
	QueueFree(q);
}

// tests enqueueing and dequeueing at capacity
static void testQueue2(void) {
	Queue q = QueueNew();
	
	// enqueue 1 to 16
	for (int i = 1; i <= 16; i++) {
		QueueEnqueue(q, i);
		assert(QueueSize(q) == i);
	}
	
	// dequeue 1 to 8, enqueue 17 to 24
	for (int i = 17, j = 1; i <= 24; i++, j++) {
		assert(QueueFront(q) == j);
		assert(QueueDequeue(q) == j);
		QueueEnqueue(q, i);
	}
	
	assert(QueueSize(q) == 16);
	QueueFree(q);
}

// tests resizing of the queue
static void testQueue3(void) {
	Queue q = QueueNew();
	
	// enqueue 1 to 24
	for (int i = 1; i <= 24; i++) {
		QueueEnqueue(q, i);
	}
	
	// dequeue 1 to 8
	for (int j = 1; j <= 8; j++) {
		assert(QueueDequeue(q) == j);
	}
	
	// dequeue 9 to 72, enqueue 25 to 88
	for (int i = 25, j = 9; i <= 88; i++, j++) {
		QueueEnqueue(q, i);
		assert(QueueDequeue(q) == j);
	}
}

static void testQueue4(void) {
	// TODO: For you to test your CircularArrayQueue
	printf("Remove this when you have added tests to this function\n");
}

