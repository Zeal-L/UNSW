// A student record

#ifndef RECORD_H
#define RECORD_H

#define MIN_ZID 1
#define MAX_ZID 9999999

#define MAX_FAMILY_NAME_LENGTH 15
#define MAX_GIVEN_NAME_LENGTH 15

typedef struct record *Record;

/**
 * Creates a record with the given zid, family name, and given name.
 * Returns NULL if any of these are invalid.
 */
Record RecordNew(int zid, char *familyName, char *givenName);

/**
 * Frees all memory allocated to the given record
 */
void RecordFree(Record r);

/**
 * Returns the zid contained in the given record
 */
int RecordGetZid(Record r);

/**
 * Returns the family name contained in the given record. The returned
 * string should not be modified or freed.
 */
char *RecordGetFamilyName(Record r);

/**
 * Returns the given name contained in the given record. The returned
 * string should not be modified or freed.
 */
char *RecordGetGivenName(Record r);

/**
 * Displays the record in the format:
 * zid|family name|given name
 */
void RecordShow(Record r);

#endif
