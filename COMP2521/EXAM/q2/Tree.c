
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "Record.h"
#include "Tree.h" // contains struct definitions

////////////////////////////////////////////////////////////////////////
// Auxiliary functions

typedef unsigned long long uint64;

static void doTreeFree(Node n, bool freeRecords);
static Node doTreeInsert(Tree t, Node n, Record rec, bool *res);
static Node newNode(Record rec);
static void doTreeShow(Node n, int level, uint64 arms);

////////////////////////////////////////////////////////////////////////

/**
 * Creates  a  new tree that will use the given comparison function. The
 * comparison function must take two records and return:
 * - a negative number if the first record is considered to be less than
 *   then second
 * - zero if the records are considered equal
 * - a positive number if the first record is considered to  be  greater
 *   than the second
 */
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

/**
 * Frees the given tree. If freeRecords is true, also frees the records.
 */
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

/**
 * Inserts  the given record using normal BST insertion using the tree's
 * comparison function. Returns true  if  the  record  was  successfully
 * inserted,  or  false  if  there was already a record in the tree that
 * compares equal to the given record. Assumes that the given tree is  a
 * BST.
 */
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

/**
 * Displays the structure of the given tree
 */
void TreeShow(Tree t) {
    doTreeShow(t->root, 0, 0);
}

// This  function  uses a hack to determine when to draw the arms of the
// tree and relies on the tree not being too tall
static void doTreeShow(Node n, int level, uint64 arms) {
    if (n == NULL) {
        printf("X\n");
        return;
    }

    RecordShow(n->rec);
    printf("\n");

    for (int i = 0; i < level; i++) {
        if ((1LLU << i) & arms) {
            printf("|     ");
        } else {
            printf("      ");
        }
    }
    printf("%s", "+--L: ");
    if (n->left != NULL) {
        arms |= (1LLU << level);
    } else {
        arms &= ~(1LLU << level);
    }
    doTreeShow(n->left, level + 1, arms);

    for (int i = 0; i < level; i++) {
        if ((1LLU << i) & arms) {
            printf("|     ");
        } else {
            printf("      ");
        }
    }
    printf("+--R: ");
    arms &= ~(1LLU << level);
    doTreeShow(n->right, level + 1, arms);
}

////////////////////////////////////////////////////////////////////////

