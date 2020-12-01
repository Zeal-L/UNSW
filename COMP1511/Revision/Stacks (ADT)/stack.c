// Zeal L (abc982210694@gmail.com)
// 2020-11-29 19:00:27
// Zid: z5325156
// 

#include "stack.h"
#include <stdlib.h>
#include <assert.h>

struct node {
    char item;
    struct node *next;
};

struct stack {
    int size;
    struct node *top;
};

Stack stackCreate() {
    Stack s = malloc(sizeof(struct stack));
    assert(s != NULL);
    s->size = 0;
    s->top = NULL;
    return s;
}

void stackFree(Stack s) {
    while (s->top != NULL) {
        pop(s);
    }
    free(s);
}

void push(char c, Stack s) {
    Node n = malloc(sizeof(struct node));
    n->item = c;
    n->next = s->top;
    s->top = n;
    s->size++;
}

char pop(Stack s) {
    assert(s->top != NULL);
    Node to_free = s->top;
    char c = to_free->item;
    s->top = to_free->next;
    free(to_free);
    s->size--;
    return c;
}

char peek(Stack s) {
    return s->top->item;
}

int getSize(Stack s) {
    return s->size;
}


