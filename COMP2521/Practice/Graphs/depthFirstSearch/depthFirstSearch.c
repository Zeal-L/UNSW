
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"

// Your task is to write a function, depthFirstSearch, that performs a 
// depth first search on a graph starting at the given vertex. It should 
// print out the vertices as they are visited. If a vertex has multiple 
// neighbours, visit the neighbour with the smallest vertex number first.
// Hint: You are not provided with a stack ADT, so you must use recursion.

static void dfs(Graph g, int src, int *visited);

void depthFirstSearch(Graph g, int src) {
	
	int *visited = calloc(GraphNumVertices(g), sizeof(int));
	dfs(g, src, visited);
	
	free(visited);
}

static void dfs(Graph g, int src, int *visited) {
	visited[src] = 1;
	printf("%d ", src);
	for (int i = 0; i < GraphNumVertices(g); i++) {
		if (GraphIsAdjacent(g, src, i)) {
			if (visited[i] == 0) {
				dfs(g, i, visited);
			}
		}
	}
}