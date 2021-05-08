
#include "list.h"

// Your task is to write a function, listSetDifference, that takes 
// two lists, l1 and l2, that represent sets and returns a new list 
// representing the set difference (l1 - l2). The values in the returned 
// list may be in any order - the testing program will sort the list 
// before displaying it. Since the lists l1 and l2 represent sets, 
// you may assume that no value appears more than once in a list. 
// You should not modify the given lists.

List listSetDifference(List l1, List l2) {
	List new = newList();
	Node curr_s1 = l1->head;
	Node track = NULL;
	
	while (curr_s1) {
		Node curr_s2 = l2->head;
		int check = 0;
		while (curr_s2) {
			if (curr_s1->value == curr_s2->value) {
				check++;
			}
			curr_s2 = curr_s2->next;
		}
		if (check == 0) {
			if (new->head == NULL) {
				new->head = newNode(curr_s1->value);
				track = new->head;
			} else {
				track->next = newNode(curr_s1->value);
				track = track->next;
			}
		}
		curr_s1 = curr_s1->next;
	}
	return new;
}

