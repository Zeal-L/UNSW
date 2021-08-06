/*

A simple example which launches two threads of execution.

    $ gcc -pthread two_threads.c -o two_threads
    $ ./two_threads | more
    Hello this is thread #1 i=0
    Hello this is thread #1 i=1
    Hello this is thread #1 i=2
    Hello this is thread #1 i=3
    Hello this is thread #1 i=4
    Hello this is thread #2 i=0
    Hello this is thread #2 i=1
    ...

*/

#include <pthread.h>
#include <stdio.h>

// This function is called to start thread execution.
// It can be given any pointer as an argument.
void *run_thread (void *argument)
{
	int *p = argument;

	for (int i = 0; i < 10; i++) {
		printf ("Hello this is thread #%d: i=%d\n", *p, i);
	}

	// A thread finishes when either the thread's start function
	// returns, or the thread calls `pthread_exit(3)'.
	// A thread can return a pointer of any type --- that pointer
	// can be fetched via `pthread_join(3)'
	return NULL;
}

int main (void)
{
	// Create two threads running the same task, but different inputs.

	pthread_t thread_id1;
	int thread_number1 = 1;
	pthread_create (&thread_id1, NULL, run_thread, &thread_number1);

	pthread_t thread_id2;
	int thread_number2 = 2;
	pthread_create (&thread_id2, NULL, run_thread, &thread_number2);

	// Wait for the 2 threads to finish.
	pthread_join (thread_id1, NULL);
	pthread_join (thread_id2, NULL);

	return 0;
}