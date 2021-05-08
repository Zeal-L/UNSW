
#include "tree.h"

// Your task is to write a function, TreeCopy, that copies a tree up to 
// a given depth. If the given depth is negative, you should return an 
// empty tree. If the given depth is greater than the height of the tree, 
// you should return a copy of the entire tree. Do NOT modify the given tree.

static Tree newTreeNode(int value);
static void doTreeCopy(Tree t, Tree copy, int depth, int count) ;

Tree TreeCopy(Tree t, int depth) {
	if (depth < 0) return NULL;

	Tree copy = newTreeNode(t->value);
	if (depth == 0) return copy;

	int count = 0;
	doTreeCopy(t, copy, depth, count);

	return copy;
}

static void doTreeCopy(Tree t, Tree copy, int depth, int count) {
	if (count++ == depth) return;

	if (t->left) {
		copy->left = newTreeNode(t->left->value);
		doTreeCopy(t->left, copy->left, depth, count);
	}
	if (t->right) {
		copy->right = newTreeNode(t->right->value);
		doTreeCopy(t->right, copy->right, depth, count);
	}
}

static Tree newTreeNode(int value) {
	Tree t = malloc(sizeof(*t));
	if (t == NULL) {
		fprintf(stderr, "Insufficient memory!\n");
		exit(EXIT_FAILURE);
	}
	t->value = value;
	t->left = NULL;
	t->right = NULL;
	return t;
}
