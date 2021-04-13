// Interface  for  a  directed  weighted graph ADT, where each vertex is
// identified by a number between 0 and N - 1, where N is the number  of
// vertices.
// COMP2521 Assignment 2

// Note: This  implementation  is provided to you, you should not modify
//       it.

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"

struct GraphRep{
	int nV;
	AdjList *outLinks;
	AdjList *inLinks;
};

static bool validVertex(Graph g, Vertex v);
static AdjList newAdjNode(Vertex v, int weight);
static AdjList adjListInsert(AdjList l, Vertex v, int weight);
static AdjList adjListDelete(AdjList l, Vertex v);
static bool inAdjList(AdjList l, Vertex v);
static void freeAdjList(AdjList l);
static void showAdjList(AdjList l);

////////////////////////////////////////////////////////////////////////
// Constructor/Destructor

Graph GraphNew(int nVertices) {
	assert(nVertices > 0);
	
	Graph g = malloc(sizeof(*g));
	if (g == NULL) {
		fprintf(stderr, "Couldn't allocate Graph!\n");
		exit(EXIT_FAILURE);
	}
	
	g->nV = nVertices;
	g->outLinks = calloc(nVertices, sizeof(AdjList));
	g->inLinks  = calloc(nVertices, sizeof(AdjList));
	
	if (g->outLinks == NULL || g->inLinks == NULL) {
		fprintf(stderr, "Couldn't allocate Graph!\n");
		exit(EXIT_FAILURE);
	}
	
	return g;
}


void GraphFree(Graph g) {
	assert(g != NULL);
	
	for (Vertex i = 0; i < g->nV; i++) {
		freeAdjList(g->outLinks[i]);
		freeAdjList(g->inLinks[i]);
	}
	free(g->outLinks);
	free(g->inLinks);
	free(g);
}

////////////////////////////////////////////////////////////////////////
// Basic Graph Operations

void GraphInsertEdge(Graph g, Vertex src, Vertex dest, int weight) {
	assert(g != NULL);
	assert(validVertex(g, src));
	assert(validVertex(g, dest));
	assert(weight > 0);
	
	g->outLinks[src] = adjListInsert(g->outLinks[src], dest, weight);
	g->inLinks[dest] = adjListInsert(g->inLinks[dest], src, weight);
}

void GraphRemoveEdge(Graph g, Vertex src, Vertex dest) {
	assert(g != NULL);
	assert(validVertex(g, src));
	assert(validVertex(g, dest));
	
	g->outLinks[src] = adjListDelete(g->outLinks[src], dest);
	g->inLinks[dest] = adjListDelete(g->inLinks[dest], src);
}

bool GraphIsAdjacent(Graph g, Vertex src, Vertex dest) {
	assert(g != NULL);
	assert(validVertex(g, src));
	assert(validVertex(g, dest));
	
	return inAdjList(g->outLinks[src], dest);
}

int GraphNumVertices(Graph g) {
	assert(g != NULL);
	return g->nV;
}

AdjList GraphOutIncident(Graph g, Vertex v) {
	assert(g != NULL);
	assert(validVertex(g, v));
	
	return g->outLinks[v];
}

AdjList GraphInIncident(Graph g, Vertex v) {
	assert(g != NULL);
	assert(validVertex(g, v));
	
	return g->inLinks[v];
}

////////////////////////////////////////////////////////////////////////
// Debugging

void GraphShow(Graph g) {
	printf("#vertices = %d\n", g->nV);
	printf("Vertices:\n");
	for (Vertex i = 0; i < g->nV; i++) {
		printf(" Vertex %2d\n", i);
		printf("  Outlinks: ");
		showAdjList(g->outLinks[i]);
		printf("  In-links: ");
		showAdjList(g->inLinks[i]);
		printf("\n");
	}
}

////////////////////////////////////////////////////////////////////////
// Helper Functions

/**
 * Check if a given vertex is valid for a graph
 */
static bool validVertex(Graph g, Vertex v) {
	return (v >= 0 && v < g->nV);
}

/**
 * Creates a new AdjList node with the given vertex and weight.
 */
static AdjList newAdjNode(Vertex v, int weight) {
	AdjList newNode = malloc(sizeof(*newNode));
	if (newNode == NULL) {
		fprintf(stderr, "Couldn't allocate new node!\n");
		exit(EXIT_FAILURE);
	}
	
	newNode->v = v;
	newNode->weight = weight;
	newNode->next = NULL;
	return newNode;
}

/*
 * Inserts  an  AdjList  node  with the given vertex and weight into the
 * given adjacency list, if the vertex  is  not  already  in  the  list.
 * Ensures the adjacency list remains ordered by vertex number.
 */
static AdjList adjListInsert(AdjList l, Vertex v, int weight) {
	if (l == NULL || v < l->v) {
		AdjList n = newAdjNode(v, weight);
		n->next = l;
		return n;
	} else if (v > l->v) {
		l->next = adjListInsert(l->next, v, weight);
		return l;
	} else {
		return l;
	}
}

/*
 * Deletes  the  AdjNode  node  with  the  given  vertex  from the given
 * adjacency list, if it  exists. Ensures  the  adjacency  list  remains
 * ordered by vertex number.
 */
static AdjList adjListDelete(AdjList l, Vertex v) {
	if (l == NULL || v < l->v) {
		return l;
	} else if (v == l->v) {
		AdjList temp = l->next;
		free(l);
		return temp;
	} else {
		l->next = adjListDelete(l->next, v);
		return l;
	}
}

/**
 * Checks  if a vertex is in the given adjacency list, returning true or
 * false as appropriate
 */
static bool inAdjList(AdjList l, Vertex v) {
	if (l == NULL || v < l->v) {
		return false;
	} else if (v == l->v) {
		return true;
	} else {
		return inAdjList(l->next, v);
	}
}

/**
 * Frees all of the memory associated with the given adjacency list. 
 */
static void freeAdjList(AdjList l) {
	if (l != NULL) {
		freeAdjList(l->next);
		free(l);
	}
}

/**
 * Outputs the given adjacency list to stdout.
 */
static void showAdjList(AdjList l) {
	while (l != NULL) {
		printf("(v: %2d, weight: %2d) -> ", l->v, l->weight);
		l = l->next;
	}
	printf("X\n");
}

