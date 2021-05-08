
#include <stdlib.h>

#include "BSTree.h"

// Your task is to write a function, BSTreeNodeDepth, that returns the 
// depth of the node containing the given key in the tree if it exists, 
// or -1 otherwise.

int BSTreeNodeDepth(BSTree t, int key) {

	if (t == NULL) {
		return -1;
	} else if (t->value == key) {
		return 0;
	} else if (key < t->value) {
		int ndl = BSTreeNodeDepth(t->left, key);
		if (ndl == -1) return -1;
		return ndl + 1;
	} else {
		int ndr = BSTreeNodeDepth(t->right, key);
		if (ndr == -1) return -1;
		return ndr + 1;
	}
}

