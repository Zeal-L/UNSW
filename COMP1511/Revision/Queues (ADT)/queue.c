// Zeal L (abc982210694@gmail.com)
// 2020-11-29 21:08:59
// Zid: z5325156
// 

#include "queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

struct node {
    char item;
    struct node *next;
};

struct queue {
    int size;
    struct node *front;
    struct node *back;
};

Queue queueCreate(void) {
    Queue q = malloc(sizeof(struct queue));
    assert(q != NULL);
    q->size = 0;
    q->front = NULL;
    q->back = NULL;
    return q;
}

void queueFree(Queue q) {
    while (q->front != NULL) {
        dequeue(q);
    }
    free(q);
}

void enqueue(Queue q, char c) {
    Node n = malloc(sizeof (struct node));
    n->item = c;
    n->next = NULL;

    if (q->front == NULL) {
        q->front = n;
        q->back = n;
    } else {
        q->back->next = n;
        q->back = n;
    }
    q->size++;
}

char dequeue(Queue q) {
    assert(q->front != NULL);
    Node to_free = q->front;
    char c = q->front->item;
    q->front = q->front->next;
    free(to_free);
    q->size--;
    return c;
}

char peek(Queue q) {
    return q->front->item;
}

int getSize(Queue q) {
    return q->size;
}

void show(Queue q) {
    Node curr = q->front;
    while (curr != NULL) {
        printf("%c ", curr->item);
        curr = curr->next;
    }
    printf("\n");
}