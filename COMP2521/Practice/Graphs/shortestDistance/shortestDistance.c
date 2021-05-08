
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"
#include "Queue.h"

// Your task is to write a function, shortestDistance, that returns the 
// number of edges on the shortest path between two vertices in the given 
// graph. If there is no path between the two vertices, return -1.

static bool bfs(Graph g, Queue q, int dest, int *visited);

int shortestDistance(Graph g, int src, int dest) {
	int num = GraphNumVertices(g);
	int *visited = malloc(num * sizeof(int));
	for(int i = 0; i < num; i++) visited[i] = -1;

	Queue q = QueueNew();
	QueueEnqueue(q, src);

	if (bfs(g, q, dest, visited)) {
		int num_edges = 0;
		while (dest != src) {
			num_edges++;
			dest = visited[dest];
		}
		QueueFree(q);
		free(visited);
		return num_edges;
	} 

	QueueFree(q);
	free(visited);
	return -1;
}

static bool bfs(Graph g, Queue q, int dest, int *visited) {
	while (!QueueIsEmpty(q)) {
		int src = QueueDequeue(q);
		if (src == dest) return true;
		for(int i = 0; i < GraphNumVertices(g); i++) {
			if (GraphIsAdjacent(g, src, i) && visited[i] == -1) {
				visited[i] = src;
				QueueEnqueue(q, i);
			}
		}
	}
	return false;
}
