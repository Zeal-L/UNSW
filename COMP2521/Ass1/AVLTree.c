
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "List.h"
#include "Record.h"
#include "AVLTree.h"

typedef struct node *Node;
struct node {
    Record rec;
    Node   left;
    Node   right;
    int    height;
};

struct tree {
    Node    root;
    int     (*compare)(Record, Record);
};

////////////////////////////////////////////////////////////////////////
// Auxiliary functions

static void doTreeFree(Node n, bool freeRecords);
static Node newNode(Record rec);
static Record doTreeSearch(Tree t, Node n, Record rec);

////////////////////////////////////////////////////////////////////////

static Node newNode(Record rec) {
    Node n = malloc(sizeof(*n));
    if (n == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    n->rec = rec;
    n->left = NULL;
    n->right = NULL;
    n->height = 0;
    return n;
}

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
/* IMPORTANT: 
   Do NOT modify the code above this line. 
   You must not modify the 'node' and 'tree' structures defined above.
   You must not modify the functions defined above.
*/
////////////////////////////////////////////////////////////////////////

#define MAX(a, b)   (a > b ? a : b) // Return the maximum value
#define GET_H(t)   (t == NULL ? -1 : t->height) // Get Height
#define L(n) (n->left) // Get Left Child
#define R(n) (n->right) // Get Right Child

static Node doTreeInsert(Tree t, Node n, Record rec, bool *res);
static Node rotateRight(Node n1);
static Node rotateLeft(Node n2);

static void doTreeSearchBetween(Tree t, Node n, Record lower,
                                Record upper, List l);

static Record doTreeNext(Tree t, Node n, Record rec);

static void Display(Node root, int ident);


////////////////////////////////////////////////////////////////////////

bool TreeInsert(Tree t, Record rec) {
    bool res = false; 
    t->root = doTreeInsert(t, t->root, rec, &res);
    return res;
}

static Node doTreeInsert(Tree t, Node n, Record rec, bool *res) {
    if (!n) {
        *res = true;
        return newNode(rec);
    } else if (t->compare(rec, n->rec) == 0) {
        return n;
    } else {
        int cmp = t->compare(rec, n->rec);
        if (cmp < 0) {
            L(n) = doTreeInsert(t, L(n), rec, res);
        } else if (cmp > 0) {
            R(n) = doTreeInsert(t, R(n), rec, res);
        }
        int l_height = GET_H(L(n));
        int r_height = GET_H(R(n));
        if (l_height - r_height > 1) {
            if (t->compare(rec, L(n)->rec) > 0)
                L(n) = rotateLeft(L(n));
            n = rotateRight(n);
        } else if (r_height - l_height > 1) {
            if (t->compare(rec, R(n)->rec) < 0)
                R(n) = rotateRight(R(n));
            n = rotateLeft(n);
        }
        n->height = MAX(GET_H(L(n)), GET_H(R(n))) + 1;
        return n;
    }
}

static Node rotateRight(Node n1) {
    if (!n1 || !n1->left) 
        return n1;
    Node n2 = n1->left;
    n1->left = n2->right;
    n2->right = n1;

    n1->height = MAX(GET_H(L(n1)), GET_H(R(n1))) + 1;
    n2->height = MAX(GET_H(L(n2)), GET_H(R(n2))) + 1;
    return n2;
}

static Node rotateLeft(Node n2) {
    if (!n2 || !n2->right)
        return n2;
    Node n1 = n2->right;
    n2->right = n1->left;
    n1->left = n2;

    n2->height = MAX(GET_H(L(n2)), GET_H(R(n2))) + 1;
    n1->height = MAX(GET_H(L(n1)), GET_H(R(n1))) + 1;
    return n1;
}

////////////////////////////////////////////////////////////////////////

List TreeSearchBetween(Tree t, Record lower, Record upper) {
    List l = ListNew();
    doTreeSearchBetween(t, t->root, lower, upper, l);
    return l;
}

static void doTreeSearchBetween(Tree t, Node n, Record lower,
                                Record upper, List l) {
    if (n == NULL) return;
    if (t->compare(lower, n->rec) <= 0) {
        doTreeSearchBetween(t, L(n), lower, upper, l);
        if (t->compare(upper, n->rec) >= 0)
            ListAppend(l, n->rec);
    }
    if (t->compare(upper, n->rec) >= 0)
        doTreeSearchBetween(t, R(n), lower, upper, l);
}

////////////////////////////////////////////////////////////////////////

Record TreeNext(Tree t, Record r) {
    //Display(t->root, 0);
    return doTreeNext(t, t->root, r);
}

static Record doTreeNext(Tree t, Node n, Record rec) {
    if (!n) return NULL;
    int cmp = t->compare(rec, n->rec);
    if (cmp <= 0) {
        Record temp = doTreeNext(t, L(n), rec);
        return temp ? temp : n->rec;
    } else {
        return doTreeNext(t, R(n), rec);
    }
}

// An array, the length of the array is not less than the height of the binary tree, 
// here it is assumed to be one hundred
// Used to mark whether the current node is the left or right children of the parent node, 
// since left and right are handled a bit differently.
static int vec_left[100];

// The function to display the binary tree, just call Display(root, 0)
static void Display(Node root, int ident) {
    if (ident > 0) {
        for(int i = 0; i < ident - 1; ++i) {
            printf(vec_left[i] ? "│   " : "    ");
        }
        printf(vec_left[ident-1] ? "├── " : "└── ");
    }

    if (!root) {
        printf("(null)\n");
        return;
    }

    printf("%d  %d:%d\n", RecordGetDepartureDay(root->rec), 
        RecordGetDepartureHour(root->rec), RecordGetDepartureMinute(root->rec));
    //printf("%d\n", root->height);
    if (!root->left && !root->right) return;

    vec_left[ident] = 1;
    Display(root->left, ident + 1);
    vec_left[ident] = 0;
    Display(root->right, ident + 1);
}