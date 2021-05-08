
#include <stdio.h>

#include "BSTree.h"

// Your task is to write a function, BSTreePostfix, 
// that prints out the values of the given BST in 
// postfix order. The values should be printed out 
// space-separated on a single line.

void BSTreePostfix(BSTree t) {
	if (!t) return;

	BSTreePostfix(t->left);
	BSTreePostfix(t->right);

	printf("%d ", t->value);
}

