
#ifndef STUDENT_DB_H
#define STUDENT_DB_H

#include "List.h"
#include "Record.h"

typedef struct studentDb *StudentDb;

/**
 * Creates a new student DB
 */
StudentDb DbNew(void);

/**
 * Frees all memory allocated to the given student DB
 */
void      DbFree(StudentDb db);

/**
 * Inserts a student record into the given DB if there is not already
 * a record with the same zid. If inserted successfully, this function
 * takes ownership of the given record (so the caller should not modify
 * or free it). Returns true if the record was successfully inserted,
 * and false if the DB already contained a record with the same zid.
 */
bool      DbInsertRecord(StudentDb db, Record r);

/**
 * Deletes a student record with the given zid from the DB. Returns true
 * if the record was successfully deleted, and false if there was no
 * record with that zid.
 */
bool      DbDeleteByZid(StudentDb db, int zid);

/**
 * Searches for a record with the given zid. Returns the record if it
 * was found, or NULL otherwise. The returned record should not be
 * modified or freed.
 */
Record    DbFindByZid(StudentDb db, int zid);

/**
 * Searches for all records with the given name, and returns them all
 * in a list. Records with the same name are ordered by zid. Returns an
 * empty list if there are no such records. The records in the returned
 * list should not be freed, but it is the caller's responsibility to
 * free the list itself.
 */
List      DbFindByName(StudentDb db, char *familyName, char *givenName);

/**
 * Displays all records in order of zid, one per line.
 */
void      DbListByZid(StudentDb db);

/**
 * Displays all records in order of name (family name first), one per
 * line. Records with the same name are ordered by zid.
 */
void      DbListByName(StudentDb db);

#endif
