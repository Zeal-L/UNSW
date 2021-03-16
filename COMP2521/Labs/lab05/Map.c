// An implementation of the Map ADT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Map.h"

typedef struct node *Node;
struct node {
    char *key;
    int   value;
    Node  left;
    Node  right;
};

struct map {
    Node  root;
};

static void  doFree(Node n);
static Node  doSet(Node n, char *key, int value);
static Node  newNode(char *key, int value);
static char *myStrdup(char *s);
static bool  doContains(Node n, char *key);
static int   doGet(Node n, char *key);

////////////////////////////////////////////////////////////////////////
// Creates a new map

Map MapNew(void) {
    Map m = malloc(sizeof(*m));
    if (m == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }
    m->root = NULL;
    return m;
}

////////////////////////////////////////////////////////////////////////
// Frees all memory allocated for the given map

void MapFree(Map m) {
    doFree(m->root);
    free(m);
}

static void doFree(Node n) {
    if (n != NULL) {
        doFree(n->left);
        doFree(n->right);
        free(n->key);
        free(n);
    }
}

////////////////////////////////////////////////////////////////////////
// Adds  a  key-value  pair to the map. If the key already exists in the
// map, its value is replaced with the given value. Makes a copy of  the
// key.
// Complexity: Assume O(log n) (even though it isn't)

void MapSet(Map m, char *key, int value) {
    m->root = doSet(m->root, key, value);
}

static Node doSet(Node n, char *key, int value) {
    if (n == NULL) {
        return newNode(key, value);
    }

    int cmp = strcmp(key, n->key);
    if (cmp < 0) {
        n->left = doSet(n->left, key, value);
    } else if (cmp > 0) {
        n->right = doSet(n->right, key, value);
    } else { // (cmp == 0)
        n->value = value;
    }
    return n;
}

static Node newNode(char *key, int value) {
    Node n = malloc(sizeof(*n));
    if (n == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }

    n->key = myStrdup(key);
    n->value = value;
    n->left = NULL;
    n->right = NULL;
    return n;
}

static char *myStrdup(char *s) {
    char *copy = malloc((strlen(s) + 1) * sizeof(char));
    if (copy == NULL) {
        fprintf(stderr, "Insufficient memory!\n");
        exit(EXIT_FAILURE);
    }
    return strcpy(copy, s);
}

////////////////////////////////////////////////////////////////////////
// Checks if the map contains the given key
// Complexity: Assume O(log n) (even though it isn't)

bool MapContains(Map m, char *key) {
    return doContains(m->root, key);
}

static bool doContains(Node n, char *key) {
    if (n == NULL) {
        return false;
    }

    int cmp = strcmp(key, n->key);
    if (cmp < 0) {
        return doContains(n->left, key);
    } else if (cmp > 0) {
        return doContains(n->right, key);
    } else {
        return true;
    }
}

////////////////////////////////////////////////////////////////////////
// Gets  the  value associated with the given key. The key is assumed to
// exist.
// Complexity: Assume O(log n) (even though it isn't)

int MapGet(Map m, char *key) {
    return doGet(m->root, key);
}

static int doGet(Node n, char *key) {
    if (n == NULL) {
        fprintf(stderr, "KeyError: '%s' not found\n", key);
        exit(EXIT_FAILURE);
    }

    int cmp = strcmp(key, n->key);
    if (cmp < 0) {
        return doGet(n->left, key);
    } else if (cmp > 0) {
        return doGet(n->right, key);
    } else {
        return n->value;
    }
}

