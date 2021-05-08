
#include "BSTree.h"

#include <stdlib.h>

// Your task is to write a function, BSTreeGetSmallest, 
// that returns a pointer to the node containing the smallest 
// value in the given BST. If the tree is empty, return NULL.

BSTree BSTreeGetSmallest(BSTree t) {
	if (!t || !t->left) return t;
	return BSTreeGetSmallest(t->left);
}

