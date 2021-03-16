
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "List.h"
#include "StudentDb.h"
#include "Tree.h"

struct studentDb {
    Tree byZid;
    Tree byName;
};

////////////////////////////////////////////////////////////////////////
// Comparison functions

/**
 * Compares two records by zid only and returns:
 * - A negative number if the first record is less than the second
 * - Zero if the records are equal
 * - A positive number if the first record is greater than the second
 */
int compareByZid(Record r1, Record r2) {
    return RecordGetZid(r1) - RecordGetZid(r2);
}

/**
 * Compares two records by name (family name first) and then by
 * zid if the names are equal, and returns:
 * - A negative number if the first record is less than the second
 * - Zero if the records are equal
 * - A positive number if the first record is greater than the second
 */
int compareByName(Record r1, Record r2) {
    int cmp_f = strcmp(RecordGetFamilyName(r1), RecordGetFamilyName(r2));
    int cmp_g = strcmp(RecordGetGivenName(r1), RecordGetGivenName(r2));
    return cmp_f ? cmp_f : cmp_g ? cmp_g : compareByZid(r1, r2);
}

////////////////////////////////////////////////////////////////////////

StudentDb DbNew(void) {
    StudentDb db = malloc(sizeof(*db));
    if (db == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    db->byZid = TreeNew(compareByZid);
    db->byName = TreeNew(compareByName);
    return db;
}

void DbFree(StudentDb db) {
    TreeFree(db->byZid, false);
    TreeFree(db->byName, true);
    free(db);
}

////////////////////////////////////////////////////////////////////////

bool DbInsertRecord(StudentDb db, Record r) {
    if (TreeInsert(db->byZid, r)) {
        TreeInsert(db->byName, r);
        return true;
    } else {
        return false;
    }
}

////////////////////////////////////////////////////////////////////////

bool DbDeleteByZid(StudentDb db, int zid) {
    Record dummy = RecordNew(zid, "", "");
    Record r = TreeSearch(db->byZid, dummy);

    if (r != NULL) {
        TreeDelete(db->byZid, r);
        TreeDelete(db->byName, r);
        RecordFree(r);
        RecordFree(dummy);
        return true;
    } else {
        RecordFree(dummy);
        return false;
    }
}

////////////////////////////////////////////////////////////////////////

Record DbFindByZid(StudentDb db, int zid) {
    Record dummy = RecordNew(zid, "", "");
    Record r = TreeSearch(db->byZid, dummy);
    RecordFree(dummy);
    return r;
}

////////////////////////////////////////////////////////////////////////

List DbFindByName(StudentDb db, char *familyName, char *givenName) {

    Record d1 = RecordNew(MIN_ZID, familyName, givenName);
    Record d2 = RecordNew(MAX_ZID, familyName, givenName);

    List l = TreeSearchBetween(db->byName, d1 , d2);
    
    RecordFree(d1);
    RecordFree(d2);
    return l;
}

////////////////////////////////////////////////////////////////////////

void DbListByZid(StudentDb db) {
    TreeListInOrder(db->byZid);
}

void DbListByName(StudentDb db) {
    TreeListInOrder(db->byName);
}
