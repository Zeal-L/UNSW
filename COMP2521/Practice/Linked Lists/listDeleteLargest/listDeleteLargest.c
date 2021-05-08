
#include "list.h"

// Your task is to write a function, listDeleteLargest, that deletes 
// the largest value from a given list and returns the value that was 
// deleted. If the largest value occurs multiple times in the list, 
// delete only the first instance. You should not change the values 
// in any nodes or create any new nodes. Your program must not have 
// any memory leaks. You can assume that the given list is not empty.

int listDeleteLargest(List l) {
	
	int max = 0;
	Node curr = l->head;
	Node prev = NULL;
	Node d_prev = NULL;
	Node d_curr = NULL;
	while(curr) {
		if (curr->value > max) {
			max = curr->value;
			d_prev = prev;
			d_curr = curr;
		}
		prev = curr;
		curr = curr->next;
	}

	if (d_curr == l->head) { 			// Delete head case
		l->head = d_curr->next;
		free(d_curr);
	} else if (d_curr->next == NULL) {	// Delete tail case
		d_prev->next = NULL;
		free(d_curr);
	} else {							// Delete middle case
		d_prev->next = d_curr->next;
		free(d_curr);
	}


	int to_delete = max;
	return to_delete;
}

