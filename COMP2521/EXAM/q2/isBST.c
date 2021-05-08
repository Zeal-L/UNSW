// isBST.c ... implementation of isBST function

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "Tree.h"

/*
    You will submit only this one file.

    Implement the function "isBST" below. Read the exam paper for a
    detailed specification and description of your task.

    - DO NOT modify the code in any other files except for debugging
      purposes.
    - If you wish, you can add static variables and/or helper functions
      to this file.
    - DO NOT add a "main" function to this file.
*/
static bool check(Tree t, Node n);

int isBST(Tree t) {
    if(t == NULL) return 1;
    if(!check(t, t->root)) return 0;
    return 1;
}

static bool check(Tree t, Node n) {
    if(n->left != NULL) {
        if(t->compare(n->left->rec, n->rec) > 0) return false;
        if(!check(t, n->left)) return false;
    }
    if(n->right != NULL) {
        if(t->compare(n->rec, n->right->rec) > 0) return false;
        if(!check(t, n->right)) return false;
    }
    return true;
}