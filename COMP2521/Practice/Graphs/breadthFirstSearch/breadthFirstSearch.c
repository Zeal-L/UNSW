
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"
#include "Queue.h"

// Your task is to write a function, breadthFirstSearch, that performs 
// a breadth first search on a graph starting at the given vertex. 
// It should print out the vertices as they are visited. If a vertex has 
// multiple neighbours, visit the neighbour with the smallest vertex 
// number first.

static void bfs(Graph g, Queue q, int *visited);

void breadthFirstSearch(Graph g, int src) {
	int *visited = calloc(GraphNumVertices(g), sizeof(int));
	Queue q = QueueNew();
	QueueEnqueue(q, src);
	visited[src] = 1;
	bfs(g, q, visited);
	
	QueueFree(q);
	free(visited);
}

static void bfs(Graph g, Queue q, int *visited) {
	while (!QueueIsEmpty(q)) {
		int src = QueueDequeue(q);
		printf("%d ", src);
		for (int i = 0; i < GraphNumVertices(g); i++) {
			if (GraphIsAdjacent(g, src, i)) {
				if (visited[i] == 0) {
					visited[i] = 1;
					QueueEnqueue(q, i);
				}
			}
		}
	}
}