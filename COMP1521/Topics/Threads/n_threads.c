/*

Simple example of running an arbitrary number of threads.
For example::

    $ gcc -pthread n_threads.c -o n_threads
    $ ./n_threads 10
    Hello this is thread 0: i=0
    Hello this is thread 0: i=1
    Hello this is thread 0: i=2
    Hello this is thread 0: i=3
    Hello this is thread 0: i=4
    Hello this is thread 0: i=5
    Hello this is thread 0: i=6
    Hello this is thread 0: i=7
    ...

*/

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

void *run_thread (void *argument)
{
	int *p = argument;

	for (int i = 0; i < 42; i++) {
		printf ("Hello this is thread %d: i=%d\n", *p, i);
	}
	return NULL;
}

int main (int argc, char *argv[])
{
	if (argc != 2) {
		fprintf (stderr, "Usage: %s <n-threads>\n", argv[0]);
		return 1;
	}

	int n_threads = strtol (argv[1], NULL, 0);
	assert (0 < n_threads && n_threads < 100);

	pthread_t thread_id[n_threads];
	int argument[n_threads];

	for (int i = 0; i < n_threads; i++) {
		argument[i] = i;
		pthread_create (&thread_id[i], NULL, run_thread, &argument[i]);
	}

	// Wait for the threads to finish
	for (int i = 0; i < n_threads; i++) {
		pthread_join (thread_id[i], NULL);
	}

	return 0;
}