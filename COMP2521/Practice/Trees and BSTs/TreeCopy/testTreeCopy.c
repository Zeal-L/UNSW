
#include <stdio.h>
#include <stdlib.h>

#include "tree.h"

Tree TreeCopy(Tree t, int depth);

int main(void) {
	Tree t = readTree(0);
	
	printf("Enter depth: ");
	int depth = 0;
	scanf("%d", &depth);
	
	printf("Original tree:\n");
	printTree(t);
	
	Tree copy = TreeCopy(t, depth);
	
	printf("Copy of the tree up to depth %d:\n", depth);
	printTree(copy);
	
	freeTree(t);
	freeTree(copy);
}

