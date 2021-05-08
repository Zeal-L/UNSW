// calculateViralTransmission.c ... implementation of
// calculateViralTransmission function

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "Graph.h"
#include "Queue.h"

/*
    You will submit only this one file.

    Implement the function "calculateViralTransmission" below.
    Read the exam paper for a detailed specification and
    description of your task.

    - DO NOT modify the code in any other files except for debugging
      purposes.
    - If you wish, you can add static variables and/or helper functions
      to this file.
    - DO NOT add a "main" function to this file.
*/

struct graph {
    int nV;
    bool **edges;
};

static void doTrasmission(Queue q, double *trasmissionArray, int src, int dest);

void calculateViralTransmission(Graph g, int src, int srcViralLoad,
                                double *trasmissionArray) {
    for (int i = 0; i < g->nV; i++) trasmissionArray[i] = -1.0;
    trasmissionArray[src] = srcViralLoad;
    Queue q = QueueNew();

    QueueEnqueue(q, src);
    while (!QueueIsEmpty(q)) {
        int src = QueueDequeue(q);
        for (int i = 0; i < g->nV; i++) {
            if (i != src) {
                if (g->edges[src][i]) {
                    doTrasmission(q, trasmissionArray, src, i);
                }
            }  
        }
    }
    for(int i=0; i < g->nV; i++) {
        if(trasmissionArray[i] < 10 && trasmissionArray[i] != -1.00) {
            trasmissionArray[i] = 0;
        }
    }
    QueueFree(q);
}

static void doTrasmission(Queue q, double *trasmissionArray, int src, int dest) {
    if (trasmissionArray[dest] < 0 || trasmissionArray[dest] < trasmissionArray[src] * 0.6) {
        trasmissionArray[dest] = trasmissionArray[src] * 0.6;
        QueueEnqueue(q, dest);
    }
}
