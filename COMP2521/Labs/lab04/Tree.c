
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "List.h"
#include "Record.h"
#include "Tree.h"

typedef struct node *Node;
struct node {
    Record rec;
    Node   left;
    Node   right;
};

struct tree {
    Node    root;
    int     (*compare)(Record, Record);
};

////////////////////////////////////////////////////////////////////////
// Auxiliary functions

static void doTreeFree(Node n, bool freeRecords);
static Node doTreeInsert(Tree t, Node n, Record rec, bool *res);
static Node newNode(Record rec);
static Node doTreeDelete(Tree t, Node n, Record rec, bool *res);
static Node joinTrees(Node t1, Node t2);
static Record doTreeSearch(Tree t, Node n, Record rec);
static void doTreeSearchBetween(Tree t, Node n, Record lower,
                                Record upper, List l);
static void doTreeListInOrder(Node n);

////////////////////////////////////////////////////////////////////////

Tree TreeNew(int (*compare)(Record, Record)) {
    Tree t = malloc(sizeof(*t));
    if (t == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    t->root = NULL;
    t->compare = compare;
    return t;
}

////////////////////////////////////////////////////////////////////////

void TreeFree(Tree t, bool freeRecords) {
    doTreeFree(t->root, freeRecords);
    free(t);
}

static void doTreeFree(Node n, bool freeRecords) {
    if (n != NULL) {
        doTreeFree(n->left, freeRecords);
        doTreeFree(n->right, freeRecords);
        if (freeRecords) {
            RecordFree(n->rec);
        }
        free(n);
    }
}

////////////////////////////////////////////////////////////////////////

bool TreeInsert(Tree t, Record rec) {
    bool res = false; // if the record was inserted
    t->root = doTreeInsert(t, t->root, rec, &res);
    return res;
}

static Node doTreeInsert(Tree t, Node n, Record rec, bool *res) {
    if (n == NULL) {
        *res = true;
        return newNode(rec);
    }

    int cmp = t->compare(rec, n->rec);
    if (cmp < 0) {
        n->left = doTreeInsert(t, n->left, rec, res);
    } else if (cmp > 0) {
        n->right = doTreeInsert(t, n->right, rec, res);
    } else {
        *res = false;
    }
    return n;
}

static Node newNode(Record rec) {
    Node n = malloc(sizeof(*n));
    if (n == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    n->left = NULL;
    n->right = NULL;
    n->rec = rec;
    return n;
}

////////////////////////////////////////////////////////////////////////

bool TreeDelete(Tree t, Record rec) {
    bool res = false;
    t->root = doTreeDelete(t, t->root, rec, &res);
    return res;
}

static Node doTreeDelete(Tree t, Node n, Record rec, bool *res) {
    if (n == NULL) {
        *res = false;
        return NULL;
    }

    int cmp = t->compare(rec, n->rec);
    if (cmp < 0) {
        n->left = doTreeDelete(t, n->left, rec, res);
    } else if (cmp > 0) {
        n->right = doTreeDelete(t, n->right, rec, res);
    } else {
        *res = true;
        Node l = n->left;
        Node r = n->right;
        free(n);
        n = joinTrees(l, r);
    }

    return n;
}

static Node joinTrees(Node t1, Node t2) {
    if (t1 == NULL) {
        return t2;
    } else if (t2 == NULL) {
        return t1;
    } else {
        Node curr = t2;
        Node prev = NULL;
        while (curr->left != NULL) {
            prev = curr;
            curr = curr->left;
        }

        if (prev != NULL) {
            prev->left = curr->right;
            curr->right = t2;
        }

        curr->left = t1;
        return curr;
    }
}

////////////////////////////////////////////////////////////////////////

Record TreeSearch(Tree t, Record rec) {
    return doTreeSearch(t, t->root, rec);
}

static Record doTreeSearch(Tree t, Node n, Record rec) {
    if (n == NULL) {
        return NULL;
    }

    int cmp = t->compare(rec, n->rec);
    if (cmp < 0) {
        return doTreeSearch(t, n->left, rec);
    } else if (cmp > 0) {
        return doTreeSearch(t, n->right, rec);
    } else {
        return n->rec;
    }
}

////////////////////////////////////////////////////////////////////////

List TreeSearchBetween(Tree t, Record lower, Record upper) {
    List l = ListNew();

    doTreeSearchBetween(t, t->root, lower, upper, l);

    return l;
}

// n - the current node
// l - a list to accumulate results
static void doTreeSearchBetween(Tree t, Node n, Record lower,
                                Record upper, List l) {
    if (n == NULL) return;
    if (t->compare(lower, n->rec) <= 0) {
        doTreeSearchBetween(t, n->left, lower, upper, l);
        if (t->compare(upper, n->rec) >= 0)
            ListAppend(l, n->rec);
    }
    if (t->compare(upper, n->rec) >= 0)
        doTreeSearchBetween(t, n->right, lower, upper, l);
    
}

////////////////////////////////////////////////////////////////////////

void TreeListInOrder(Tree t) {
    doTreeListInOrder(t->root);
}

static void doTreeListInOrder(Node n) {
    if (n != NULL) {
        doTreeListInOrder(n->left);
        RecordShow(n->rec);
        printf("\n");
        doTreeListInOrder(n->right);
    }
}
