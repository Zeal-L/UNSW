
#include "list.h"

// Your task is to write a function, listSetUnion, that takes two 
// lists representing two sets and returns a new list that represents 
// the union of those sets. For example, if the two lists are [4, 3, 1, 7, 6]
// and [3, 2, 5, 1, 6], you should return a list containing the elements 
// 1, 2, 3, 4, 5, 6, and 7. The result list does not have to be ordered 
// in any particular way. Since the input lists represent sets, you can 
// assume they do not contain any duplicate elements. Your function must
// not modify the input lists.

static void findnew(Node s, List new);

List listSetUnion(List s1, List s2) {
	
	List new = newList();
	
	findnew(s1->head, new);
	findnew(s2->head, new);
	
	return new;
}

static void findnew(Node s, List new) {
	while(s) {
		Node temp = new->head;
		if (temp == NULL) {
				new->head = newNode(s->value);
		} else {
			int check = 0;
			while(temp){
				if (s->value == temp->value) check++;
				temp = temp->next;
			}
			if (check == 0) {
				Node t = new->head;
				new->head = newNode(s->value);
				new->head->next = t;
			}
		}
		s = s->next;
	}
}