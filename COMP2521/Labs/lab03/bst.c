// bst.c ... client for BSTree ADT

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "BSTree.h"

#define MAXVALS 1000

int main(void)
{
	// Build BST from values in stdin
	BSTree T = BSTreeNew();
	int nvals = 0;
	int v[MAXVALS];
	
	int n;
	while (nvals < MAXVALS && scanf("%d", &n) == 1) {
		v[nvals++] = n;
		T = BSTreeInsert(T, n);
	}

	// Display information about constructed tree
	printf("Tree:\n");
	BSTreePrint(T);
	printf("\n");
	printf("#nodes = %d,  ", BSTreeNumNodes(T));
	printf("#leaves = %d\n", BSTreeNumLeaves(T));

	printf("Infix  : "); BSTreeInfix(T); printf("\n");
	printf("Prefix : "); BSTreePrefix(T); printf("\n");
	printf("Postfix: "); BSTreePostfix(T); printf("\n");
	printf("ByLevel: "); BSTreeLevelOrder(T); printf("\n");

	// Check correctness of tree
	// Every inserted value can be found
	for (int i = 0; i < nvals; i++) {
		assert(BSTreeFind(T, v[i]) != 0);
	}

	BSTreeFree(T);
	return EXIT_SUCCESS;
}

