
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Record.h"


struct record {
    int zid;
    char familyName[MAX_FAMILY_NAME_LENGTH + 1];
    char givenName[MAX_GIVEN_NAME_LENGTH + 1];
};


Record RecordNew(int zid, char *familyName, char *givenName) {
    if (zid < MIN_ZID || zid > MAX_ZID) {
        fprintf(stderr, "error: invalid zid '%d'\n", zid);
        return NULL;
    }

    if (strlen(familyName) > MAX_FAMILY_NAME_LENGTH) {
        fprintf(stderr, "error: family name '%s' is too long\n", familyName);
        return NULL;
    }

    if (strlen(givenName) > MAX_GIVEN_NAME_LENGTH) {
        fprintf(stderr, "error: given names '%s' is too long\n", givenName);
        return NULL;
    }

    Record r = malloc(sizeof(*r));
    if (r == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    r->zid = zid;
    strcpy(r->familyName, familyName);
    strcpy(r->givenName, givenName);
    return r;
}

void RecordFree(Record r) {
    free(r);
}

int RecordGetZid(Record r) {
    return r->zid;
}

char *RecordGetFamilyName(Record r) {
    return &(r->familyName[0]);
}

char *RecordGetGivenName(Record r) {
    return &(r->givenName[0]);
}

void RecordShow(Record r) {
    printf("%d|%s|%s", RecordGetZid(r), RecordGetFamilyName(r),
           RecordGetGivenName(r));
}
