
#include <stdio.h>
#include <stdlib.h>

#include "BSTree.h"
static BSTree newBSTNode(int value);

// Your task is to write a function, BSTreeInsert, 
// that inserts a given value into a BST, if it does 
// not already exist in the BST, and returns the root 
// of the updated BST. The insertion should be performed 
// using normal leaf insertion. Do not rebalance the tree. 
// If the value already exists in the BST, the function 
// should do nothing.

BSTree BSTreeInsert(BSTree t, int val) {
	
	if (t == NULL) return newBSTNode(val);

	if (val < t->value) t->left = BSTreeInsert(t->left, val);
	else if (val > t->value) t->right = BSTreeInsert(t->right, val);

	return t;
}

static BSTree newBSTNode(int value) {
	BSTree t = malloc(sizeof(*t));
	if (t == NULL) {
		fprintf(stderr, "Insufficient memory!\n");
		exit(EXIT_FAILURE);
	}
	t->value = value;
	t->left = NULL;
	t->right = NULL;
	return t;
}
