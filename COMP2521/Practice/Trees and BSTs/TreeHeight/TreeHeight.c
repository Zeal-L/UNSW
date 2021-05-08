
#include <stdlib.h>

#include "tree.h"

// Your task is to write a function, TreeHeight, that returns the height 
// of the given tree. The height of a tree is the number of edges on the 
// longest path from the root node to a leaf node. The height of an empty 
// tree is considered to be -1.

int TreeHeight(Tree t) {
    if (t == NULL) {
		return -1;
	} else {
		int lh = TreeHeight(t->left);
		int rh = TreeHeight(t->right);
		return 1 + ((lh > rh) ? lh : rh);
	}
}

