
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "BSTree.h"
#include "GraphRead.h"
#include "GirvanNewman.h"

void printClusters(Tree t, int depth) {
	// To avoid infinite looping, due to a possible  
	// incorrect logic in the program being tested!
	assert(depth < 200);
	
	printf("%d: {", depth);
	printTree(t);	
	printf("}");

	if ((getLeftTree(t) == NULL) && (getRightTree(t) == NULL)) {
		printf(" (leaf)");
	}
	printf("\n");
}

Tree printDendrogram(Dendrogram dn, int depth) {
	// To avoid infinite looping, due to a possible  
	// incorrect logic in the program being tested!
	assert( depth < 200 );

	Tree tr = NULL;
	Tree tl = NULL;
	if (dn == NULL) return NULL;
	
	if (dn->left == NULL && dn->right == NULL) {
		Tree t = newTree();
		t = TreeInsert(t, dn->vertex);
		return t;
	}
	
	if (dn->left != NULL) {
		tl = printDendrogram(dn->left, depth + 1);
		printClusters(tl, depth);
	}
	
	if (dn->right != NULL) {
		tr = printDendrogram(dn->right, depth + 1);
		printClusters(tr, depth);
	}
	
	Tree bothTrees = addTree(tl, tr);
	freeTree(tr);
	return bothTrees;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: ./testGirvanNewman [file]\n");
		return EXIT_FAILURE;
	}
	
	Graph g = readGraph(argv[1]);

	Dendrogram dn = GirvanNewman(g);
	Tree allTree = printDendrogram(dn, 1);
	printClusters(allTree, 0);
	freeTree(allTree);
	freeDendrogram(dn);
	
	GraphFree(g);	
}

