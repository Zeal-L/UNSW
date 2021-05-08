
#include "list.h"

// Your task is to write a function, reverseDLList, that reverses a 
// given doubly linked list. You should not change the values in any 
// nodes or create any new nodes - instead, you should rearrange the 
// nodes of the given list.

void reverseDLList(List l) {
	
	Node prev = NULL;
    Node curr = l->first;
    l->last = curr;
    while (curr) {
        Node next = curr->next;
        curr->next = prev;
		curr->prev = next;

        prev = curr;
        curr = next;
    }

    l->first = prev;
}

