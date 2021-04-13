// Floyd Warshall ADT interface
// COMP2521 Assignment 2

// Note: You MUST NOT modify this file.

#ifndef FLOYD_WARSHALL_H
#define FLOYD_WARSHALL_H

#include <limits.h>
#include <stdbool.h>

#include "Graph.h"

#define INFINITY INT_MAX

typedef struct ShortestPaths {
	int numNodes; // The number of vertices in the graph
	
	int **dist;   // A matrix of shortest path distances between each
	              // pair of vertices. dist[v][w] contains the shortest
	              // distance from v to w.
	              // - The distance from a vertex to itself is 0.
	              // - If there is no path from v to w, the distance
	              //   should be set to INFINITY (#defined above)
	                 
	int **next;   // A matrix of "next vertex"s - one for each pair of
	              // vertices. next[v][w] contains the next vertex of
	              // vertex v along the shortest path from v to w.
	              // - For all v, next[v][v] should be set to -1.
	              // - If there is no path from v to w, next[v][w]
	              //   should be set to -1.
} ShortestPaths;

/**
 * Finds all shortest paths between all pairs of nodes.
 * 
 * The  function  returns  a 'ShortestPaths' structure with the required
 * information:
 * - the number of vertices in the graph
 * - distance matrix
 * - matrix of intermediates (see description above)
 */
ShortestPaths FloydWarshall(Graph g);

/**
 * This  function  is  for  you to print out the ShortestPaths structure
 * while you are debugging/testing your implementation. 
 * 
 * We will not call this function during testing, so you may  print  out
 * the  given  ShortestPaths  structure in whatever format you want. You
 * may choose not to implement this function.
 */
void showShortestPaths(ShortestPaths sps);

/**
 * Frees  all  memory associated with the given ShortestPaths structure.
 * We will call this function during testing, so you must implement it.
 */
void freeShortestPaths(ShortestPaths sps);

#endif

