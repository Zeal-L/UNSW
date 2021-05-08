// testIsBST.c

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "Tree.h"

int isBST(Tree t);

static int compareByZid(Record r1, Record r2);

static Tree getTree1(void);
static Tree getTree2(void);
static Tree getTree3(void);
// add prototypes for your own tests here

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <test-number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    Tree t;
    switch (atoi(argv[1])) {
        case 1:  t = getTree1(); break;
        case 2:  t = getTree2(); break;
        case 3:  t = getTree3(); break;
        // add cases for your own tests here
        default:
            fprintf(stderr, "%s: error: invalid test number '%s'\n",
                    argv[0], argv[1]);
            exit(EXIT_FAILURE);
    }

    printf("Tree:\n");
    TreeShow(t);
    printf("\n");

    int res = isBST(t);
    printf("isBST returned: %d\n", res);

    TreeFree(t, true);
}

////////////////////////////////////////////////////////////////////////

/**
 * Compares two records by zid only and returns:
 * - A negative number if the first record is less than the second
 * - Zero if the records are equal
 * - A positive number if the first record is greater than the second
 */
static int compareByZid(Record r1, Record r2) {
    return RecordGetZid(r1) - RecordGetZid(r2);
}

// add comparison functions for your own tests here

////////////////////////////////////////////////////////////////////////

static Tree getTree1(void) {
    printf("Using comparison function: compareByZid\n\n");

    Tree t = TreeNew(compareByZid);
    TreeInsert(t, RecordNew(50, "Smith", "John"));
    TreeInsert(t, RecordNew(65, "Ng", "Rita"));

    return t;
}

static Tree getTree2(void) {
    printf("Using comparison function: compareByZid\n\n");

    Tree t = TreeNew(compareByZid);
    TreeInsert(t, RecordNew(50, "Smith", "John"));
    TreeInsert(t, RecordNew(65, "Ng", "Rita"));
    TreeInsert(t, RecordNew(14, "Brown", "Kylie"));

    return t;
}

static Tree getTree3(void) {
    printf("Using comparison function: compareByZid\n\n");

    Tree t = TreeNew(compareByZid);
    TreeInsert(t, RecordNew(50, "Jones", "Ram"));
    TreeInsert(t, RecordNew(80, "Lee", "Emma"));
    TreeInsert(t, RecordNew(72, "Brown", "Olivia"));
    TreeInsert(t, RecordNew(91, "Yang", "Sophia"));
    TreeInsert(t, RecordNew(35, "Singh", "Samuel"));
    TreeInsert(t, RecordNew(12, "Zhou", "Layla"));

    // make the tree unordered
    RecordFree(t->root->left->rec);
    t->root->left->rec = RecordNew(65, "Singh", "Samuel");

    return t;
}

// add functions for your own tests here

