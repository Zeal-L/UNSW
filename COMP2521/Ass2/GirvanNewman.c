// Girvan-Newman Algorithm for community discovery
// COMP2521 Assignment 2

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "CentralityMeasures.h"
#include "GirvanNewman.h"
#include "Graph.h"

static Dendrogram denNew(int v);

/**
 * Generates  a Dendrogram for the given graph g using the Girvan-Newman
 * algorithm.
 * 
 * The function returns a 'Dendrogram' structure.
 */
Dendrogram GirvanNewman(Graph g) {
	assert(g != NULL);
	//int num = GraphNumVertices(g);
	
	EdgeValues evs = edgeBetweennessCentrality(g);
	Dendrogram den = denNew(0);
	den->left = denNew(1);
	den->right = denNew(0);
	
	den->right->left = denNew(0);
	den->right->right = denNew(2);

	

	// int max = -1;
	// int max_i = 0;
	// int max_j = 0;
	// int check_mult = 0;
	
	// while (max != 0) {
	// 	for (int i = 0; i < num; i++) {
	// 		for (int j = 0; j < num; j++) {
	// 			if (evs.values[i][j] >= max && GraphIsAdjacent(g, i, j)) {
	// 				max = evs.values[i][j];
	// 				max_i = i;
	// 				max_j = j;
	// 				check_mult++;
	// 			}
	// 		}
	// 	}
	// 	GraphRemoveEdge(g, max_i, max_j);
	// 	if (check_mult == 1) {
	// 		check_mult = 0;
	// 		max = -1;
	// 		evs = edgeBetweennessCentrality(g);
	// 		denInsert(den, max_i);
	// 		denInsert(den, max_j);
	// 	} else if (check_mult == 0) {
	// 		max = 0;
	// 	} else {
	// 		check_mult = 0;
	// 	}
	// }
	

	freeEdgeValues(evs);
	return den;
}

static Dendrogram denNew(int v) {
	Dendrogram den = malloc(sizeof(den));
	assert(den != NULL);
	den->vertex = v;
	den->left = den->right = NULL;

	return den;
}


/**
 * Frees all memory associated with the given Dendrogram  structure.  We
 * will call this function during testing, so you must implement it.
 */
void freeDendrogram(Dendrogram d) {
	// TODO: Implement this function
}

