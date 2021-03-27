// A student record

#ifndef RECORD_H
#define RECORD_H

#define MAX_FLIGHT_NUMBER 8
#define MAX_AIRPORT_NAME  8

typedef struct record *Record;

/**
 * Creates  a  record  with  the given flight number, departure airport,
 * arrival airport, departure time (consisting of day, hour, and minute)
 * and flight duration (in minutes).
 * Returns NULL if any of these are invalid.
 */
Record RecordNew(char *flightNumber,  
                 char *departureAirport, char *arrivalAirport, 
                 int departureDay, int departureHour, int departureMinute,
                 int durationMinutes);

/**
 * Frees all memory allocated to the given record
 */
void RecordFree(Record r);

/**
 * Returns the day contained in the given record
 */
int RecordGetDepartureDay(Record r);

/**
 * Returns the hour contained in the given record
 */
int RecordGetDepartureHour(Record r);

/**
 * Returns the minute contained in the given record
 */
int RecordGetDepartureMinute(Record r);

/**
 * Returns the duration contained in the given record
 */
int RecordGetDurationMinutes(Record r);

/**
 * Returns the flight number contained in the given record. The returned
 * string should not be modified or freed.
 */
char *RecordGetFlightNumber(Record r);

/**
 * Returns  the  departure airport number contained in the given record.
 * The returned string should not be modified or freed.
 */
char *RecordGetDepartureAirport(Record r);

/**
 * Returns the arrival airport number contained in the given record. The
 * returned string should not be modified or freed.
 */
char *RecordGetArrivalAirport(Record r);

/**
 * Displays the record. 
 */
void RecordShow(Record r);

#endif
