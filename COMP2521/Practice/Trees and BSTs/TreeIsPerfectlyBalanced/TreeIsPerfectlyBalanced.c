
#include <stdlib.h>

#include "tree.h"

// Your task is to write a function, TreeIsPerfectlyBalanced, that 
// determines whether a given tree is perfectly balanced. A tree is 
// perfectly balanced if, for every node, the difference in size 
// (i.e., number of nodes) between its left and right subtrees does 
// not exceed 1. The function should return true if the tree is 
// perfectly balanced, and false otherwise.

#define NOT_HEIGHT_BALANCED -99

int isHeightBalanced(Tree t);

bool TreeIsPerfectlyBalanced(Tree t) {
	
	if (isHeightBalanced(t) == NOT_HEIGHT_BALANCED) return false;

	return true;
}

int isHeightBalanced(Tree t) {
	if (t == NULL) return 0;

	int hl = isHeightBalanced(t->left);
	int hr = isHeightBalanced(t->right);

	// at least one of the subtrees is not height balanced
	if (hl == NOT_HEIGHT_BALANCED || hr == NOT_HEIGHT_BALANCED)
		return NOT_HEIGHT_BALANCED;

	int diff = hl - hr;
	// absolute diff is more than one, so not height balanced
	if (diff < -1 || diff > 1)
		return NOT_HEIGHT_BALANCED;

	// so far the tree is height balanced; return number of nodes
    return hl + hr + 1;
}