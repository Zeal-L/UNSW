// Interface  for  a  directed  weighted graph ADT, where each vertex is
// identified by a number between 0 and N - 1, where N is the number  of
// vertices.
// COMP2521 Assignment 2

// Note: You MUST NOT modify this file.

#ifndef GRAPH_H
#define GRAPH_H

#include <stdbool.h>

typedef struct GraphRep *Graph;

typedef int Vertex;

typedef struct adjListNode *AdjList;
struct adjListNode {
	Vertex v;
	int weight;
	struct adjListNode *next;
};

////////////////////////////////////////////////////////////////////////
// Constructor/Destructor

/**
 * Creates a new graph with the given number of vertices.
 */
Graph GraphNew(int nVertices);

/**
 * Frees all of the memory associated with the given graph.
 */
void GraphFree(Graph g);

////////////////////////////////////////////////////////////////////////
// Basic Graph Operations

/**
 * Inserts  an edge from 'src' to 'dest' with the given weight. If there
 * is already an edge from 'src' to 'dest', this function does nothing.
 */
void GraphInsertEdge(Graph g, Vertex src, Vertex dest, int weight);

/**
 * Removes  the  edge  from 'src' to 'dest' from the given graph. If the
 * graph has no edge from 'src' to 'dest', this function does nothing.
 */
void GraphRemoveEdge(Graph g, Vertex src, Vertex dest);

/**
 * Returns  true  if  there is an edge from 'src' to 'dest' in the given
 * graph, and false otherwise.
 */
bool GraphIsAdjacent(Graph g, Vertex src, Vertex dest);

/**
 * Returns the number of vertices in the given graph.
 */
int GraphNumVertices(Graph g);

/**
 * Returns a list containing (destination vertex, weight) pairs for each
 * outgoing  edge  from  vertex  'v',  where weight is the weight of the
 * edge.  The  list  will be ordered by vertex number. The user must not
 * modify or free the list.
 */
AdjList GraphOutIncident(Graph g, Vertex v);

/**
 * Returns  a  list  containing  (source vertex, weight)  pairs for each
 * incoming edge to vertex 'v', where weight is the weight of the  edge.
 * The  list  will be ordered by vertex number. The user must not modify
 * or free the list.
 */
AdjList GraphInIncident(Graph g, Vertex v);

////////////////////////////////////////////////////////////////////////
// Debugging

/**
 * Prints the graph to stdout.
 */
void GraphShow(Graph g);

#endif

