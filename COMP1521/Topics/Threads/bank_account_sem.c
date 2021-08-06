/*

Simple example demonstrating ensuring safe access to a global variable
from threads using a semaphore.

	$ gcc -O3 -pthread bank_account_semphore.c -o bank_account_semphore
	$ ./bank_account_semphore
	Andrew's bank account has $200000
	$

*/

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>

int bank_account = 0;

sem_t bank_account_semaphore;

// add $1 to Andrew's bank account 100,000 times
void *add_100000 (void *argument)
{
	for (int i = 0; i < 100000; i++) {
		// decrement bank_account_semaphore if > 0
		// otherwise wait until > 0
		sem_wait (&bank_account_semaphore);

		// only one thread can execute this section of code at any time
		// because  bank_account_semaphore was initialized to 1

		bank_account = bank_account + 1;

		// increment bank_account_semaphore
		sem_post (&bank_account_semaphore);
	}

	return NULL;
}

int main (void)
{
	// initialize bank_account_semaphore to 1
	sem_init (&bank_account_semaphore, 0, 1);

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

	sem_destroy (&bank_account_semaphore);
	return 0;
}