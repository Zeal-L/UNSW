// Girvan-Newman Algorithm for community discovery
// COMP2521 Assignment 2

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "CentralityMeasures.h"
#include "GirvanNewman.h"
#include "FloydWarshall.h"
#include "Graph.h"

static Dendrogram denNew(int v);
static void removeHighestEdges(Graph g, bool *isolatedV, int *componentA, int *componentB);

static int checkSingleIsolated(bool *isolatedV, int num);
static Dendrogram doGirvanNewman(Graph g, Dendrogram den, bool *isolatedV);

/**
 * Generates  a Dendrogram for the given graph g using the Girvan-Newman
 * algorithm.
 * 
 * The function returns a 'Dendrogram' structure.
 */
Dendrogram GirvanNewman(Graph g) {
	assert(g != NULL);
	ShortestPaths paths = FloydWarshall(g);
	Dendrogram den = denNew(-1);
	int num = GraphNumVertices(g);
	bool isolatedV[num];
	for (int i = 0; i < num; i++) isolatedV[i] = true;

	doGirvanNewman(g, den, isolatedV);
	
	freeShortestPaths(paths);
	return den;
}

static Dendrogram doGirvanNewman(Graph g, Dendrogram den, bool *isolatedV) {
	
	int num = GraphNumVertices(g);

	// Stop cases
	int single = checkSingleIsolated(isolatedV, num);
	if (single >= 0) {	// Single component left.
		isolatedV[single] = false;
		return denNew(single);

	} else if (single == -2) { // Last Two component in that subtree.
		for (int i = 0; i < num; i++) {
			if (isolatedV[i] == true) {
				isolatedV[i] = false;
				if (den->left == NULL) den->left = denNew(i);
				else if (den->right == NULL) den->right = denNew(i);
			}
		}
		return NULL;
	}
	
	int componentA = 0;
	int componentB = 0;
	bool *isolatedA = malloc(sizeof(bool) * num);
	bool *isolatedB = malloc(sizeof(bool) * num);
	for (int i = 0; i < num; i++) isolatedA[i] = isolatedB[i] = false;
	
	if (single == -1) removeHighestEdges(g, isolatedV, &componentA, &componentB);
	
	ShortestPaths paths = FloydWarshall(g);
	// Updata isolatedA and isolatedB after removeHighestEdges.
	for (int i = 0; i < num; i++) {
		if (paths.dist[componentA][i] != INFINITY 
			|| paths.dist[i][componentA] != INFINITY) {
			isolatedA[i] = true;
		} else if (paths.dist[componentB][i] != INFINITY 
			|| paths.dist[i][componentB] != INFINITY) {
			isolatedB[i] = true;
		}
	}
	freeShortestPaths(paths);
	

	int singleA = checkSingleIsolated(isolatedA, num);
	int singleB = checkSingleIsolated(isolatedB, num);

	// Different recursion cases.
	if (singleA < 0) { // Two or more Vertexs in one component case.
		den->left = denNew(-1);
		doGirvanNewman(g, den->left, isolatedA);
	} else { // Single Vertex case.
		den->left = doGirvanNewman(g, den, isolatedA);
	}
	// Same as above but in right subtree.
	if (singleB < 0) {
		den->right = denNew(-1);
		doGirvanNewman(g, den->right, isolatedB);
	} else {
		den->right = doGirvanNewman(g, den, isolatedB);
	}

	free(isolatedA);
	free(isolatedB);
	return NULL;
}

// remove Highest Edges in the given graph
// If there are muilple sedges with the same 
// Betweenness Centrality Remove them simultaneously.
// componentA and B record the index of the two components created after removal.
static void removeHighestEdges(Graph g, bool *isolatedV, int *componentA, int *componentB) {
	EdgeValues evs = edgeBetweennessCentrality(g);
	int num = GraphNumVertices(g);
	int max = -1;
	int max_i = 0;
	int max_j = 0;
	int check_mult = 0;

	while (max != 0) {
		for (int i = 0; i < num; i++) {
			for (int j = 0; j < num; j++) {
				if (evs.values[i][j] >= max && GraphIsAdjacent(g, i, j) 
					&& isolatedV[i] && isolatedV[j]) { // make sure we only remove 
					max = evs.values[i][j];			   // edges in curr component
					max_i = i;
					max_j = j;
					check_mult++;
				}
			}
		}
		
		GraphRemoveEdge(g, max_i, max_j);
		ShortestPaths paths = FloydWarshall(g);
		if (paths.dist[max_i][max_j] == INFINITY 
			&& paths.dist[max_j][max_i] == INFINITY) {
			*componentA = max_i;
			*componentB = max_j;
		} 
		freeShortestPaths(paths);
		
		if (check_mult == 0) max = 0;
		check_mult = 0;
	}

	// In case if no two new components are created after 
	// removingHighestEdges, then continue to removeHighestEdges.
	ShortestPaths p = FloydWarshall(g);
	if (p.dist[*componentA][*componentB] != INFINITY) {
		removeHighestEdges(g, isolatedV, componentA, componentB);
	}
	freeShortestPaths(p);
	
	freeEdgeValues(evs);
}

// Check if there is a single componet in the given array
// Return positive number as index when there're only one component.
// Return -2 is there are two components left.
// Return -1 is there are more then 2 components.
static int checkSingleIsolated(bool *isolatedV, int num) {
	int counter = 0;
	int single = -1;
	for (int i = 0; i < num; i++) {
		if (isolatedV[i] == true) {
			single = i;
			counter++;
		}
	}
	if (counter == 1) return single;
	if (counter == 2) return -2;
	return -1;
}

static Dendrogram denNew(int v) {
	Dendrogram den = malloc(sizeof(*den));
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
	if (d == NULL) return;
	freeDendrogram(d->left);
	freeDendrogram(d->right);
	free(d);
}
