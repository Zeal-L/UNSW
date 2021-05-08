
#include "list.h"

// Your task is to write a function, listIsPalindromic, that 
// determines whether the sequence of values in a given doubly 
// linked list is palindromic. A sequence of values is palindromic 
// if it reads the same backwards as forwards. For example, the 
// sequence [1, 2, 3, 2, 1] is palindromic, whereas the sequence 
// [1, 2, 3, 4] is not. The function should return true if the 
// sequence of values in the linked list is palindromic, and 
// false otherwise. Your function should not modify the list.

bool listIsPalindromic(List l) {
	
	Node front = l->first;
	Node back = l->last;
	for(int i = 0; i < l->size / 2; i++) {
		if (front->value != back->value) return false;
		front = front->next;
		back = back->prev;
	}

	return true;
}

