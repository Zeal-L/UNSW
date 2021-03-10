
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "List.h"
#include "Record.h"
#include "Tree.h"

// In StudentDb.c
int compareByZid(Record r1, Record r2);
int compareByName(Record r1, Record r2);

static void usage(char *progname);

static void testCompareByName(void);
static void doTestCompareByName(int zid1, char *fName1, char *gName1,
                                int zid2, char *fName2, char *gName2);

static void testTreeSearchBetween(void);
static void doTestTreeSearchBetween(int zids[], int numZids,
                                    int lowerZid, int upperZid);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
    }

    int choice = atoi(argv[1]);
    switch (choice) {
        case 1:  testCompareByName();     break;
        case 2:  testTreeSearchBetween(); break;
        default: usage(argv[0]);          break;
    }
}

static void usage(char *progname) {
    printf("Usage: %s <1-2>\n", progname);
    exit(EXIT_FAILURE);
}

////////////////////////////////////////////////////////////////////////

static void testCompareByName(void) {
    printf("Testing compareByName\n");

    doTestCompareByName(1, "Doe", "John", 2, "May", "Jane");
    doTestCompareByName(1, "May", "John", 2, "Doe", "Jane");
    doTestCompareByName(1, "Doe", "Jane", 2, "Doe", "John");
    doTestCompareByName(1, "Doe", "John", 2, "Doe", "Jane");
    doTestCompareByName(1, "Doe", "John", 2, "Doe", "John");
    doTestCompareByName(1, "Doe", "John", 1, "Doe", "John");
    doTestCompareByName(2, "Doe", "John", 1, "Doe", "John");
}

static void doTestCompareByName(int zid1, char *fName1, char *gName1,
                                int zid2, char *fName2, char *gName2)
{
    Record r1 = RecordNew(zid1, fName1, gName1);
    Record r2 = RecordNew(zid2, fName2, gName2);

    printf("\nComparing:\n");
    printf("A = "); RecordShow(r1); printf("\n");
    printf("B = "); RecordShow(r2); printf("\n");
    printf("compareByName says: ");

    int cmp = compareByName(r1, r2);
    if (cmp < 0) {
        printf("A is less than B\n");
    } else if (cmp == 0) {
        printf("A is equal to B\n");
    } else {
        printf("A is greater than B\n");
    }

    RecordFree(r1);
    RecordFree(r2);
}

////////////////////////////////////////////////////////////////////////

static void testTreeSearchBetween(void) {
    printf("Testing TreeSearchBetween\n");

    int zids1[] = {11, 13, 17, 19, 23, 29, 31, 37, 41, 43};

    doTestTreeSearchBetween(zids1, 10, 17, 31);
    doTestTreeSearchBetween(zids1, 10, 38, 49);
    doTestTreeSearchBetween(zids1, 10, 10, 20);
    doTestTreeSearchBetween(zids1, 10, 32, 35);

    int zids2[] = {29, 17, 11, 13, 23, 19, 41, 31, 37, 43};

    doTestTreeSearchBetween(zids2, 10, 22, 38);
    doTestTreeSearchBetween(zids2, 10, 12, 35);
    doTestTreeSearchBetween(zids2, 10, 30, 38);
    doTestTreeSearchBetween(zids2, 10, 40, 47);
}

static void doTestTreeSearchBetween(int zids[], int numZids,
                                    int lowerZid, int upperZid)
{
    Tree t = TreeNew(compareByZid);

    printf("\nInserting:");
    for (int i = 0; i < numZids; i++) {
        printf(" %d", zids[i]);
        TreeInsert(t, RecordNew(zids[i], "Doe", "John"));
    }
    printf("\n");

    printf("Searching between %d and %d\n", lowerZid, upperZid);

    Record lowerDummy = RecordNew(lowerZid, "", "");
    Record upperDummy = RecordNew(upperZid, "", "");
    
    List l = TreeSearchBetween(t, lowerDummy, upperDummy);

    printf("Search returned:");
    ListIterator it = ListItNew(l);
    while (ListItHasNext(it)) {
        printf(" %d", RecordGetZid(ListItNext(it)));
    }
    printf("\n");
    ListItFree(it);

    ListFree(l);
    RecordFree(lowerDummy);
    RecordFree(upperDummy);
    TreeFree(t, true);
}

////////////////////////////////////////////////////////////////////////
