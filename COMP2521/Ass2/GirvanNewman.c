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
static void removeHighestEdges(Graph g, int *componentA, int *componentB);
static int checkSingleComponent(Graph g, bool *isolatedV);
static bool checkAllIsolated(Graph g, bool *isolatedV);

// static Graph componentGraph(Graph g, ShortestPaths paths, int v);
// static void DFSsearch(Graph g, Graph newG, bool *visited, int v);

/**
 * Generates  a Dendrogram for the given graph g using the Girvan-Newman
 * algorithm.
 * 
 * The function returns a 'Dendrogram' structure.
 */
Dendrogram GirvanNewman(Graph g) {
	assert(g != NULL);
	int num = GraphNumVertices(g);
	
	//ShortestPaths paths = FloydWarshall(g);
	Dendrogram den = denNew(-2);

	Dendrogram curr = den;
	int componentA = 0;
	int componentB = 0;

	bool isolatedV[num];
	for (int i = 0; i < num; i++) isolatedV[i] = false;

	while (checkAllIsolated(g, isolatedV) == false) {
		removeHighestEdges(g, &componentA, &componentB);
		int c = checkSingleComponent(g, isolatedV);
		
		if (c == -1) {	// No New SingleComponent
			curr->left = denNew(-1);
			curr->right = denNew(-1);
		
		} else if (c >= 0) {	// One New SingleComponent
			// if (curr->left != NULL 
			// 	&& curr->right != NULL
			// 	&& curr->left->vertex == -1 
			// 	&& curr->right->vertex == -1) {
			// 	curr = curr->left;
			// }

			curr->left = denNew(c);
			curr = curr->right = denNew(-1);

		} else if (c == -2) {	// Two New SingleComponent
			for (int i = 0; i < num; i++) {
				if (isolatedV[i] != true) {
					isolatedV[i] = true;
					if (curr->left == NULL) curr->left = denNew(i);
					else if (curr->right == NULL) curr->right = denNew(i);
				}
			}
		}
		
	}
	
	// freeShortestPaths(paths);
	return den;
}

static int checkSingleComponent(Graph g, bool *isolatedV) {
	int c = 0;
	int counter = 0;
	for(int i = 0; i < GraphNumVertices(g); i++) {
		if (isolatedV[i] == true) continue;
		if (GraphOutIncident(g, i) == NULL && GraphInIncident(g, i) == NULL ) {
			counter++;
			c = i;
		}
	}
	if (counter == 1) {
		isolatedV[c] = true;
		return c;
	} else if (counter == 2) {
		return -2;
	}
	return -1;
}

static bool checkAllIsolated(Graph g, bool *isolatedV) {
	for (int i = 0; i < GraphNumVertices(g); i++) {
		if (isolatedV[i] == false) return false;
	}
	return true;
}

static void removeHighestEdges(Graph g, int *componentA, int *componentB) {
	EdgeValues evs = edgeBetweennessCentrality(g);
	int num = GraphNumVertices(g);
	int max = -1;
	int max_i = 0;
	int max_j = 0;
	int check_mult = 0;

	while (max != 0) {
		for (int i = 0; i < num; i++) {
			for (int j = 0; j < num; j++) {
				if (evs.values[i][j] >= max && GraphIsAdjacent(g, i, j)) {
					max = evs.values[i][j];
					max_i = i;
					max_j = j;
					check_mult++;
				}
			}
		}
		GraphRemoveEdge(g, max_i, max_j);
		if (check_mult == 0) max = 0;
		check_mult = 0;
	}
	*componentA = max_i;
	*componentB = max_j;
	freeEdgeValues(evs);
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
	if (d == NULL) return;
	freeDendrogram(d->left);
	freeDendrogram(d->right);
	free(d);
}

// static Graph componentGraph(Graph g, ShortestPaths paths, int v) {
// 	int num = 0;
// 	for(int i = 0; i < GraphNumVertices(g); i++) {
// 		if (paths.dist[v][i] != INFINITY) num++;
// 	}
// 	Graph newG = GraphNew(num);
// 	bool visited[num];
// 	for (int i = 0; i < num; i++) visited[i] = false;

// 	DFSsearch(g, newG, visited, v);
// }

// static void DFSsearch(Graph g, Graph newG, bool *visited, int v) {
// 	visited[v] = true;
// 	for (int i = 0; i < num; i++) {
// 		if (GraphIsAdjacent(g, v, i) && !visited[i]) {
// 			AdjList out = GraphOutIncident(g, v);
// 			while (out != NULL) {
// 				if (out->v == i) break;
// 				out = out->next;
// 			}
// 			GraphInsertEdge(newG, v, i, out->weight);

// 			DFSsearch(g, newG, visited, v);
// 		}
// 	}
// }