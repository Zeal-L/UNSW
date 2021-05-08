
#include "list.h"

// Your task is to write a function, listIsOrdered, that determines 
// whether a linked list is sorted in either ascending or descending 
// order. It should return true if the list is sorted in ascending or 
// descending order, and false otherwise. Your function should not 
// modify the list. An empty list is considered to be sorted.

static bool ascending(Node n);
static bool descending(Node n);

bool listIsOrdered(List l) {
	if (!l->head) return true;
	return (ascending(l->head) || descending(l->head));
}

static bool ascending(Node n) {
	if (!n->next) return true;
	return (n->value <= n->next->value) ? ascending(n->next) : false;
}

static bool descending(Node n) {
	if (!n->next) return true;
	return (n->value >= n->next->value) ? descending(n->next) : false;
}