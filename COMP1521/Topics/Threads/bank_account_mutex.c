/*

Simple example demonstrating safe access to a global variable from
threads, using a mutex (mutual exclusion) lock

    $ gcc -O3 -pthread bank_account_mutex.c -o bank_account_mutex
    $ ./bank_account_mutex
    Andrew's bank account has $200000
    $

*/

#include <pthread.h>
#include <stdio.h>

int bank_account = 0; // global

pthread_mutex_t bank_account_lock = PTHREAD_MUTEX_INITIALIZER;

// add $1 to Andrew's bank account 100,000 times
void *add_100000 (void *argument)
{
	for (int i = 0; i < 100000; i++) {
		pthread_mutex_lock (&bank_account_lock);

		// only one thread can execute this section of code at any time

		bank_account = bank_account + 1;

		pthread_mutex_unlock (&bank_account_lock);
	}

	return NULL;
}

int main (void)
{
	// create two threads performing  the same task

	pthread_t thread_id1;
	pthread_create (&thread_id1, NULL, add_100000, NULL);

	pthread_t thread_id2;
	pthread_create (&thread_id2, NULL, add_100000, NULL);

	// wait for the 2 threads to finish
	pthread_join (thread_id1, NULL);
	pthread_join (thread_id2, NULL);

	// will always be $200000
	printf ("Andrew's bank account has $%d\n", bank_account);
	return 0;
}