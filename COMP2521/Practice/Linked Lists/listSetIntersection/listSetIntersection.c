
#include "list.h"

// Your task is to write a function, listSetIntersection, that 
// takes two lists representing two sets and returns a new list 
// that represents the intersection of those sets. For example, 
// if the two lists are [4, 3, 1, 7, 6] and [3, 2, 5, 1, 6], you 
// should return a list containing the elements 1, 3, and 6. The 
// result list does not have to be ordered in any particular way. 
// Since the input lists represent sets, you can assume they do not 
// contain any duplicate elements. Your function must not modify 
// the input lists.

List listSetIntersection(List s1, List s2) {
	List new = newList();
	Node curr_s1 = s1->head;
	Node track = NULL;

	while (curr_s1) {
		Node curr_s2 = s2->head;
		while (curr_s2) {
			if (curr_s1->value == curr_s2->value) {
				if (new->head == NULL) {
					new->head = newNode(curr_s1->value);
					track = new->head;
				} else {
					track->next = newNode(curr_s1->value);
					track = track->next;
				}
			}
			curr_s2 = curr_s2->next;
		}
		curr_s1 = curr_s1->next;
	}

	return new;
}

