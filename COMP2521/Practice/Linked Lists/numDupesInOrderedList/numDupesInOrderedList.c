
#include "list.h"

// Your task is to write a function, numDupesInOrderedList, that returns 
// the number of duplicate elements in the given ordered linked list. 
// The number of duplicate elements is the minimum number of elements that 
// would need to be removed to obtain a list with no duplicates. 
// For example, the list [1, 2, 2, 3, 3, 3] contains three duplicate 
// elements, because three elements would need to be removed to obtain 
// a list with no duplicates: 2, 3, and 3. (However, you should not 
// actually remove any elements - you should simply return the number of 
// duplicate values.) Your function should not modify the list. You can 
// assume that the linked list is sorted in either ascending or descending 
// order.

int numDupesInOrderedList(List l) {
	int num = 0;
	int flag[MAX_LINE_LEN] = {0};

	Node curr = l->head;
	while (curr) {
		flag[curr->value]++;
		curr = curr->next;
	}

	for (int i = 0; i < MAX_LINE_LEN; i++) {
		if (flag[i] > 1) {
			num += flag[i] - 1;
		}
	}

	return num;
}

