
#include <stdio.h>
#include <stdlib.h>

#include "Queue.h"

int main(void) {
	
	
		Queue q = QueueNew();
		// enqueue 0 to 123456, dequeue 0 to 123456
		for (int i = 0; i <= 123456; i++) {
			QueueEnqueue(q, i);
		}
		for (int i = 0; i <= 123456; i++) {
			QueueDequeue(q);
		}
		QueueFree(q);
		
	// time ./benchmarkCircularArrayQueue 
	// user    0m0.004s
	// time ./benchmarkArrayQueue
	// user    0m27.212s
}

