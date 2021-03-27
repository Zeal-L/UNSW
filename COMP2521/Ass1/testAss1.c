// Sample tests for Assignment 1

////////////////////////////////////////////////////////////////////////
/*

IMPORTANT:
- These tests are by no means comprehensive - you should do your own
  testing by creating functions containing your own tests, and extending
  the switch statement in the main function to call these functions.

*/
////////////////////////////////////////////////////////////////////////

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "List.h"
#include "Record.h"
#include "AVLTree.h"
#include "FlightDb.h"

////////////////////////////////////////////////////////////////////////
// Auxiliary functions

static void usage(char *progName);

static void testDbNewDbFree(void);
static void testDbInsertRecord(void);
static void testDbFindByFlightNumber(void);
static void testDbFindByDepartureAirportDay(void);
static void testDbFindBetweenTimes(void);
static void testDbFindNextFlight(void);

static void doTestDbInsertRecord(Record recs[], int numRecs);
static void doTestDbFindByFlightNumber(FlightDb db, char *flightNumber);
static void doTestDbFindByDepartureAirportDay(FlightDb db,
                                              char *departureAirport,
                                              int day);
static void doTestDbFindBetweenTimes(FlightDb db,
                                     int day1, int hour1, int minute1,
                                     int day2, int hour2, int minute2);
static void doTestDbFindNextFlight(FlightDb db, char *departureAirport,
                                   int day, int hour, int minute);

static FlightDb createSampleDb(void);
static void showRecordList(List l);
static char *dayToName(int day);

////////////////////////////////////////////////////////////////////////

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
    }
    
    switch (atoi(argv[1])) {
        case 1:  testDbNewDbFree();                 break;
        case 2:  testDbInsertRecord();              break;
        case 3:  testDbFindByFlightNumber();        break;
        case 4:  testDbFindByDepartureAirportDay(); break;
        case 5:  testDbFindBetweenTimes();          break;
        case 6:  testDbFindNextFlight();            break;
        default: usage(argv[0]);                    break;
    }
}

static void usage(char *progName) {
    printf("Usage: %s <test number (1-6)>\n", progName);
    exit(EXIT_FAILURE);
}

////////////////////////////////////////////////////////////////////////

static void testDbNewDbFree(void) {
    // This test just checks that DbNew and DbFree don't cause errors
    FlightDb db = DbNew();
    DbFree(db);
    
    printf("DbNew and DbFree did not crash\n");
}

////////////////////////////////////////////////////////////////////////

static void testDbInsertRecord(void) {
    printf("Testing DbInsertRecord\n\n");

    Record recs[] = {
        RecordNew("QF409", "SYD", "MEL", 0,  7,  5,  90),
        
        // this should be rejected, because it is exactly the same as
        // the one above
        RecordNew("QF409", "SYD", "MEL", 0,  7,  5,  90),
        
        // this should be rejected even though duration is different,
        // because flight number and time are the same, 
        RecordNew("QF409", "SYD", "MEL", 0,  7,  5,  91),
        
        // this should be accepted because the time is different
        RecordNew("QF409", "SYD", "MEL", 0,  7,  6,  90),
        
        // this should be accepted because flight number is different
        RecordNew("QF401", "SYD", "MEL", 0,  7,  5,  90),
        
        // this should be accepted
        RecordNew("VA323", "MEL", "BNE", 6, 11,  0, 110),
    };
    
    doTestDbInsertRecord(recs, 6);
}

static void doTestDbInsertRecord(Record recs[], int numRecs) {
    printf("Creating the DB\n\n");
    FlightDb db = DbNew();
    
    for (int i = 0; i < numRecs; i++) {
        printf("Attempting to insert: ");
        RecordShow(recs[i]);
        printf("\n");
        
        bool result = DbInsertRecord(db, recs[i]);
        printf("Insertion %s\n", result ? "succeeded" : "failed");
        if (!result) RecordFree(recs[i]);
    }
    
    printf("\nDiscarding the DB\n");
    DbFree(db);
}

////////////////////////////////////////////////////////////////////////

static void testDbFindByFlightNumber(void) {
    printf("Testing DbFindByFlightNumber\n");
    printf("Using sample DB from testAss1.c\n\n");
    
    FlightDb db = createSampleDb();
    
    doTestDbFindByFlightNumber(db, "QF409");
    doTestDbFindByFlightNumber(db, "VA323");
    doTestDbFindByFlightNumber(db, "JQ771");
    doTestDbFindByFlightNumber(db, "JQ560");
    doTestDbFindByFlightNumber(db, "QF500");
    doTestDbFindByFlightNumber(db, "QF530");
    
    DbFree(db);
}

static void doTestDbFindByFlightNumber(FlightDb db, char *flightNumber) {
    printf("Searching for flights with flight number %s\n",
           flightNumber);
    
    List l = DbFindByFlightNumber(db, flightNumber);
    
    if (ListSize(l) == 0) {
        printf("No flights found\n");
    } else {
        printf("Found flights:\n");
        showRecordList(l);
    }
    
    printf("\n");
    ListFree(l);
}

////////////////////////////////////////////////////////////////////////

static void testDbFindByDepartureAirportDay(void) {
    printf("Testing DbFindByDepartureAirportDay\n");
    printf("Using sample DB from testAss1.c\n\n");
    
    FlightDb db = createSampleDb();
    
    doTestDbFindByDepartureAirportDay(db, "SYD", 0);
    doTestDbFindByDepartureAirportDay(db, "SYD", 1);
    doTestDbFindByDepartureAirportDay(db, "SYD", 2);
    doTestDbFindByDepartureAirportDay(db, "SYD", 3);
    doTestDbFindByDepartureAirportDay(db, "SYD", 4);
    doTestDbFindByDepartureAirportDay(db, "SYD", 5);
    doTestDbFindByDepartureAirportDay(db, "SYD", 6);
    
    DbFree(db);
}

static void doTestDbFindByDepartureAirportDay(FlightDb db,
                                              char *departureAirport,
                                              int day) {
    printf("Searching for flights from %s on %s\n",
           departureAirport, dayToName(day));
    
    List l = DbFindByDepartureAirportDay(db, departureAirport, day);
    
    if (ListSize(l) == 0) {
        printf("No flights found\n");
    } else {
        printf("Found flights:\n");
        showRecordList(l);
    }
    
    printf("\n");
    ListFree(l);
}

////////////////////////////////////////////////////////////////////////

static void testDbFindBetweenTimes(void) {
    printf("Testing DbFindBetweenTimes\n");
    printf("Using sample DB from testAss1.c\n\n");
    
    FlightDb db = createSampleDb();
    
    // First time will ALWAYS be earlier than second
    // time in ALL tests including automarking. Days
    // of the week will NOT wrap around (e.g., there
    // won't  be tests where day1 is SUNDAY and day2
    // is MONDAY)
    
    // Monday 7am-8am
    doTestDbFindBetweenTimes(db, 0,  7, 0, 0,  8,  0);
    
    // Monday 10am-2pm
    doTestDbFindBetweenTimes(db, 0, 10, 0, 0, 14,  0);
    
    // Monday morning
    doTestDbFindBetweenTimes(db, 0,  0, 0, 0, 11, 59);
    
    // Monday all day
    doTestDbFindBetweenTimes(db, 0,  0, 0, 0, 23, 59);
    
    // Weekend
    doTestDbFindBetweenTimes(db, 5,  0, 0, 6, 23, 59);
    
    // Friday afternoon
    doTestDbFindBetweenTimes(db, 4, 12, 0, 4, 16, 59);
    
    DbFree(db);
}

static void doTestDbFindBetweenTimes(FlightDb db,
                                     int day1, int hour1, int minute1,
                                     int day2, int hour2, int minute2) {
    printf("Searching for flights between %s %02d%02d and %s %02d%02d\n",
           dayToName(day1), hour1, minute1,
           dayToName(day2), hour2, minute2); 

    List l = DbFindBetweenTimes(db,
                                day1, hour1, minute1,
                                day2, hour2, minute2);
    
    if (ListSize(l) == 0) {
        printf("No flights found\n");
    } else {
        printf("Found flights:\n");
        showRecordList(l);
    }
    
    printf("\n");
    ListFree(l);
}

////////////////////////////////////////////////////////////////////////

static void testDbFindNextFlight(void) {
    printf("Testing DbFindNextFlight\n");
    printf("Using sample DB from testAss1.c\n\n");
    
    FlightDb db = createSampleDb();
    
    // DbFindNextFlight must be able to wrap around to the
    // beginning of the next week if there are no flights later
    // in the week. Note that all flights in the DB repeat every
    // week.
    
    doTestDbFindNextFlight(db, "SYD", 0,  7, 5);
    
    doTestDbFindNextFlight(db, "SYD", 0,  7, 6);
    
    doTestDbFindNextFlight(db, "SYD", 0, 14, 6);
    
    doTestDbFindNextFlight(db, "SYD", 2, 12, 0);
    
    doTestDbFindNextFlight(db, "SYD", 6, 14, 0);
    
    DbFree(db);
}

static void doTestDbFindNextFlight(FlightDb db, char *departureAirport,
                                   int day, int hour, int minute) {
    printf("Finding first available flight at %s from %s %02d%02d\n",
           departureAirport, dayToName(day), hour, minute);
    
    Record r = DbFindNextFlight(db, departureAirport, day, hour, minute);
    
    if (r == NULL) {
        printf("No flights found\n");
    } else {
        printf("Found flight:\n");
        RecordShow(r);
        printf("\n");
    }
    
    printf("\n");
}

////////////////////////////////////////////////////////////////////////

static FlightDb createSampleDb(void) {
    FlightDb db = DbNew();

    // QF409 from SYD to MEL
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 0,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 1,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 2,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 3,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 4,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 5,  7,  5,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 6,  7,  5,  90));

    // QF409 from SYD to MEL
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 0,  8,  0,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 2,  8,  0,  90));
    DbInsertRecord(db, RecordNew("QF409", "SYD", "MEL", 5,  8,  0,  90));

    // VA323 from MEL to BNE
    DbInsertRecord(db, RecordNew("VA323", "MEL", "BNE", 1, 11,  0, 110));
    DbInsertRecord(db, RecordNew("VA323", "MEL", "BNE", 3, 11, 30, 110));
    DbInsertRecord(db, RecordNew("VA323", "MEL", "BNE", 4, 11,  0, 110));
    DbInsertRecord(db, RecordNew("VA323", "MEL", "BNE", 6, 11, 30, 110));
    
    // JQ771 from ADL to MEL
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 1, 11, 55, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 3, 11, 55, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 5, 11, 55, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 6, 11, 55, 105));
    
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 0, 14,  5, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 1, 14,  5, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 2, 14,  5, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 3, 14,  5, 105));
    DbInsertRecord(db, RecordNew("JQ771", "ADL", "MEL", 4, 14,  5, 105));

    // JQ560 from MEL to BNE
    DbInsertRecord(db, RecordNew("JQ560", "MEL", "BNE", 0,  9,  0,  85));
    DbInsertRecord(db, RecordNew("JQ560", "MEL", "BNE", 1,  9,  0,  85));
    DbInsertRecord(db, RecordNew("JQ560", "MEL", "BNE", 3,  9,  0,  85));
    DbInsertRecord(db, RecordNew("JQ560", "MEL", "BNE", 4,  9,  0,  85));
    
    // QF500 from SYD to BNE
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 0,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 1,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 2,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 3,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 4,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 5,  4,  0,  30));
    DbInsertRecord(db, RecordNew("QF500", "SYD", "BNE", 6,  4,  0,  30));
    
    // QF530 from SYD to BNE
    DbInsertRecord(db, RecordNew("QF530", "SYD", "BNE", 0, 13,  5,  30));
    DbInsertRecord(db, RecordNew("QF530", "SYD", "BNE", 2, 13,  5,  30));
    DbInsertRecord(db, RecordNew("QF530", "SYD", "BNE", 3, 13,  5,  30));
    DbInsertRecord(db, RecordNew("QF530", "SYD", "BNE", 4, 13,  5,  30));
    DbInsertRecord(db, RecordNew("QF530", "SYD", "BNE", 6, 13,  5,  30));
    
    return db;
}

////////////////////////////////////////////////////////////////////////

static void showRecordList(List l) {
    ListIterator it = ListItNew(l);
    while (ListItHasNext(it)) {
        RecordShow(ListItNext(it));
        printf("\n");
    }
    ListItFree(it);
}

static char *dayToName(int day) {
    assert(day >= 0 && day <= 6);
    
    char *days[] = {
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday", "Sunday"
    };
    
    return days[day];
}

