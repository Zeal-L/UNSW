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
static bool *findComponent(Graph g, int componentV);
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
	Dendrogram den = denNew(-1);
	int num = GraphNumVertices(g);
	bool component[num];
	for (int i = 0; i < num; i++) component[i] = true;

	doGirvanNewman(g, den, component);
	
	return den;
}

static Dendrogram doGirvanNewman(Graph g, Dendrogram den, bool *component) {
	int num = GraphNumVertices(g);
	////////////////////////////////////////////////////////////////////////
	// Stop cases
	int single = checkSingleIsolated(component, num);
	if (single >= 0) {	// Single vertex left.
		return denNew(single);
	} else if (single == -2) { // Last Two vertexes in that subtree/component.
		for (int i = 0; i < num; i++) {
			if (component[i] == true) {
				if (den->left == NULL) den->left = denNew(i);
				else if (den->right == NULL) den->right = denNew(i);
			}
		}
		return NULL;
	}

	////////////////////////////////////////////////////////////////////////
	// Remove highest edges and calculate the newly created component part
	int isolated_A = 0;
	int isolated_B = 0;
	// If the number of remaining vertices is greater than 2 then keep removing it
	if (single == -1) removeHighestEdges(g, component, &isolated_A, &isolated_B);
	// Updata isolatedV and isolatedB after removeHighestEdges.
	bool *component_A = findComponent(g, isolated_A);
	bool *component_B = findComponent(g, isolated_B);
	int single_A = checkSingleIsolated(component_A, num);
	int single_B = checkSingleIsolated(component_B, num);

	////////////////////////////////////////////////////////////////////////
	// Different recursion cases.
	if (single_A < 0) { // Two or more Vertexs in one component case.
		den->left = denNew(-1);
		doGirvanNewman(g, den->left, component_A);
	} else { // Single Vertex case.
		den->left = doGirvanNewman(g, den, component_A);
	}
	// Same as above but in right subtree.
	if (single_B < 0) {
		den->right = denNew(-1);
		doGirvanNewman(g, den->right, component_B);
	} else {
		den->right = doGirvanNewman(g, den, component_B);
	}

	free(component_A);
	free(component_B);
	return NULL;
}

// remove Highest Edges in the given graph
// If there are muilple sedges with the same 
// Betweenness Centrality Remove them simultaneously.
// isolated A and B record the index of the two components created after removal.
static void removeHighestEdges(Graph g, bool *component, int *isolated_A, int *isolated_B) {
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
					&& component[i] && component[j]) { // make sure we only remove 
					max = evs.values[i][j];			   // edges in curr component
					max_i = i;
					max_j = j;
					check_mult++;
				}
			}
		}
		
		GraphRemoveEdge(g, max_i, max_j);
		ShortestPaths paths = FloydWarshall(g);
		// Confirms that the two vertices belong to different 
		// components before assigning the value to isolated A and B
		if (paths.dist[max_i][max_j] == INFINITY 
			&& paths.dist[max_j][max_i] == INFINITY) {
			*isolated_A = max_i;
			*isolated_B = max_j;
		} 
		freeShortestPaths(paths);
		
		if (check_mult == 0) max = 0;
		check_mult = 0;
	}

	// In case if no two new components are created after 
	// removingHighestEdges, then continue to removeHighestEdges.
	ShortestPaths p = FloydWarshall(g);
	if (p.dist[*isolated_A][*isolated_B] != INFINITY) {
		removeHighestEdges(g, component, isolated_A, isolated_B);
	}
	freeShortestPaths(p);
	freeEdgeValues(evs);
}

// Check if there is a single vertex in the given component
// Return positive number as index when there're only one vertex.
// Return -2 if there are two vertexes left.
// Return -1 if there are more then 2 vertexes.
static int checkSingleIsolated(bool *component, int num) {
	int counter = 0;
	int single = -1;
	for (int i = 0; i < num; i++) {
		if (component[i] == true) {
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

// Find all connected vertices based on the 
// vertice given, and return this component.
static bool *findComponent(Graph g, int isolated_V) {
	int num = GraphNumVertices(g);
	bool *component = malloc(sizeof(bool) * num);
	for (int i = 0; i < num; i++) component[i] = false;

	ShortestPaths paths = FloydWarshall(g);
	for (int i = 0; i < num; i++) {
		if (paths.dist[isolated_V][i] != INFINITY 
			|| paths.dist[i][isolated_V] != INFINITY) {
			component[i] = true;
		} 
	}
	freeShortestPaths(paths);
	return component;
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