
#include <stdlib.h>

#include "tree.h"

// Your task is to write a function, TreeSumOdds, that returns 
// the sum of all of the odd values in the given tree.

static void doTreeSumOdds(Tree t, int *sum);

int TreeSumOdds(Tree t) {
	int sum = 0;

	doTreeSumOdds(t, &sum);

	return sum;
}

static void doTreeSumOdds(Tree t, int *sum) {
	if (!t) return;
	
	doTreeSumOdds(t->left, sum);
	doTreeSumOdds(t->right, sum);

	if (t->value % 2 != 0) *sum += t->value;
}