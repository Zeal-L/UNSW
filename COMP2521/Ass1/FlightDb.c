
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "List.h"
#include "FlightDb.h"
#include "AVLTree.h"

struct flightDb {
	Tree byFN;
	Tree byDAD;
    Tree BT;
    Tree NF;
};

// In increasing order of  (day, hour, min).
int compareByFN(Record r1, Record r2) {
	int cmp_f = strcmp(RecordGetFlightNumber(r1), RecordGetFlightNumber(r2));
	int cmp_d = RecordGetDepartureDay(r1) - RecordGetDepartureDay(r2);
	int cmp_h = RecordGetDepartureHour(r1) - RecordGetDepartureHour(r2);
    int cmp_m = RecordGetDepartureMinute(r1) - RecordGetDepartureMinute(r2);
	return cmp_f ? cmp_f : cmp_d ? cmp_d : cmp_h ? cmp_h : cmp_m;

}

// In increasing order  of (hour, min, flight number).
int compareByDAD(Record r1, Record r2) {
    int cmp_a = strcmp(RecordGetDepartureAirport(r1), RecordGetDepartureAirport(r2));
    int cmp_d = RecordGetDepartureDay(r1) - RecordGetDepartureDay(r2);
	int cmp_h = RecordGetDepartureHour(r1) - RecordGetDepartureHour(r2);
    int cmp_m = RecordGetDepartureMinute(r1) - RecordGetDepartureMinute(r2);
	int cmp_f = strcmp(RecordGetFlightNumber(r1), RecordGetFlightNumber(r2));
    return cmp_a ? cmp_a : cmp_d ? cmp_d : cmp_h ? cmp_h : cmp_m ? cmp_m : cmp_f;
}

// In increasing  order  of (day, hour, min, flight number).
int compareBetweenTimes(Record r1, Record r2) {
    int cmp_d = RecordGetDepartureDay(r1) - RecordGetDepartureDay(r2);
	int cmp_h = RecordGetDepartureHour(r1) - RecordGetDepartureHour(r2);
    int cmp_m = RecordGetDepartureMinute(r1) - RecordGetDepartureMinute(r2);
	int cmp_f = strcmp(RecordGetFlightNumber(r1), RecordGetFlightNumber(r2));
    return cmp_d ? cmp_d : cmp_h ? cmp_h : cmp_m ? cmp_m : cmp_f;
}

// In increasing  order  of (day, hour, min)
int compareNextFlight(Record r1, Record r2) {
    int cmp_a = strcmp(RecordGetDepartureAirport(r1), RecordGetDepartureAirport(r2));
    int cmp_d = RecordGetDepartureDay(r1) - RecordGetDepartureDay(r2);
	int cmp_h = RecordGetDepartureHour(r1) - RecordGetDepartureHour(r2);
    int cmp_m = RecordGetDepartureMinute(r1) - RecordGetDepartureMinute(r2);
    int cmp_f = strcmp(RecordGetFlightNumber(r1), RecordGetFlightNumber(r2));
    return cmp_a ? cmp_a : cmp_d ? cmp_d : cmp_h ? cmp_h : cmp_m ? cmp_m : cmp_f;
}

/**
 * Creates a new flight DB. 
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
FlightDb DbNew(void) {
	FlightDb db = malloc(sizeof(*db));
    if (db == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    db->byFN = TreeNew(compareByFN);
    db->byDAD = TreeNew(compareByDAD);
    db->BT = TreeNew(compareBetweenTimes);
    db->NF = TreeNew(compareNextFlight);
    return db;
}

/**
 * Frees all memory allocated to the given flight DB
 */
void     DbFree(FlightDb db) {
	TreeFree(db->byFN, false);
    TreeFree(db->byDAD, false);
    TreeFree(db->BT, false);
    TreeFree(db->NF, true);
    free(db);
}

/**
 * Inserts  a  flight  record  into the given DB if there is not already
 * record with the same flight number, departure airport, day, hour  and
 * minute.
 * If  inserted successfully, this function takes ownership of the given 
 * record (so the caller should not modify or free it). 
 * Returns true if the record was successfully inserted,  and  false  if
 * the  DB  already  contained  a  record  with  the same flight number,
 * departure airport, day, hour and minute.
 * The time complexity of this function must be O(log n).
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
bool     DbInsertRecord(FlightDb db, Record r) {
	if (TreeInsert(db->byFN, r) && TreeInsert(db->byDAD, r) 
        && TreeInsert(db->BT, r) && TreeInsert(db->NF, r)) {
        return true;
    } else {
        return false;
    }
}

/**
 * Searches  for  all  records with the given flight number, and returns
 * them all in a list in increasing order of  (day, hour, min).  Returns
 * an empty list if there are no such records. 
 * The  records  in the returned list should not be freed, but it is the
 * caller's responsibility to free the list itself.
 * The time complexity of this function must be O(log n + m), where m is
 * the length of the returned list.
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
List     DbFindByFlightNumber(FlightDb db, char *flightNumber) {
	
    // Dummy records
	Record d1 = RecordNew(flightNumber, "", "", 0, 0, 00, 0);
    Record d2 = RecordNew(flightNumber, "", "", 6, 23, 59, 0);

    List l = TreeSearchBetween(db->byFN, d1 , d2);
    
    RecordFree(d1);
    RecordFree(d2);
    return l;
}

/**
 * Searches  for all records with the given departure airport and day of
 * week (0 to 6), and returns them all in a list in increasing order  of
 * (hour, min, flight number).
 * Returns an empty list if there are no such records.
 * The  records  in the returned list should not be freed, but it is the
 * caller's responsibility to free the list itself.
 * The time complexity of this function must be O(log n + m), where m is
 * the length of the returned list.
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
List     DbFindByDepartureAirportDay(FlightDb db, char *departureAirport,
                                     int day) {

    // Dummy records
	Record d1 = RecordNew("", departureAirport, "", day, 0, 00, 0);
    Record d2 = RecordNew("zzzzzzzz", departureAirport, "", day, 23, 59, 0);

    List l = TreeSearchBetween(db->byDAD, d1 , d2);
    
    RecordFree(d1);
    RecordFree(d2);
    return l;
}


/**
 * Searches  for  all  records  between  (day1, hour1, min1)  and (day2,
 * hour2, min2), and returns them all in a list in increasing  order  of
 * (day, hour, min, flight number).
 * Returns an empty list if there are no such records.
 * The  records  in the returned list should not be freed, but it is the
 * caller's responsibility to free the list itself.
 * The time complexity of this function must be O(log n + m), where m is
 * the length of the returned list.
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
List     DbFindBetweenTimes(FlightDb db, 
                            int day1, int hour1, int min1, 
                            int day2, int hour2, int min2) {

    // Dummy records
	Record d1 = RecordNew("", "", "", day1, hour1, min1, 0);
    Record d2 = RecordNew("zzzzzzzz", "", "", day2, hour2, min2, 0);

    List l = TreeSearchBetween(db->BT, d1 , d2);
    
    RecordFree(d1);
    RecordFree(d2);
    return l;
}

/**
 * Searches  for  and  returns  the  earliest next flight from the given
 * departure airport, on or after the given (day, hour, min), or NULL if
 * there is no such flight.
 * The returned record must not be freed or modified. 
 * The time complexity of this function must be O(log n).
 * You MUST use the AVLTree ADT (from Task 1) in your implementation.
 */
Record   DbFindNextFlight(FlightDb db, char *departureAirport, 
                          int day, int hour, int min) {
	
    // Dummy records
    Record dummy = RecordNew("", departureAirport, "", day, hour, min, 0);
    Record r = TreeNext(db->NF, dummy);
    // If don't find one in this week, check next week's flights
    if (!r) {
        Record next_week = RecordNew("", departureAirport, "", 0, 0, 00, 0);
        r = TreeNext(db->NF, next_week);
        RecordFree(dummy);
        RecordFree(next_week);
        return r;
    }
    RecordFree(dummy);
    return r;
}

