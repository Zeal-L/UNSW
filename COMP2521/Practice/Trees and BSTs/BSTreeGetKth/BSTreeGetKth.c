
#include <stdlib.h>

#include "BSTree.h"

// Your task is to write a function, BSTreeGetKth, that returns the 
// k'th smallest value in the given BST. You can assume that k is 
// between 0 and N - 1, where N is the size of the tree.

static void doBSTreeGetKth(BSTree t, int k, int *num, int *count);
int BSTreeGetKth(BSTree t, int k) {
	int num = 0;
	int count = 0;

	doBSTreeGetKth(t, k, &num, &count);

	return num;
}

static void doBSTreeGetKth(BSTree t, int k, int *num, int *count) {
	if (!t) return;

	doBSTreeGetKth(t->left, k, num, count);
	
	if ((*count)++ == k) *num = t->value;
	
	doBSTreeGetKth(t->right, k, num, count);
}