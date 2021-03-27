
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Record.h"

struct record {
    char flightNumber[MAX_FLIGHT_NUMBER + 1];
    char departureAirport[MAX_AIRPORT_NAME + 1];
    char arrivalAirport[MAX_AIRPORT_NAME + 1];
    int departureDay;    // 0 for Monday, ... , 6 for Sunday
    int departureHour;   // Between 0 and 23 (inclusive)
    int departureMinute; // Between 0 to 59 (inclusive)
    int durationMinutes; // Duration of the flight, in minutes
};

static char *dayToName(int day);

Record RecordNew(char *flightNumber,  
                 char *departureAirport, char *arrivalAirport, 
                 int departureDay, int departureHour, int departureMinute,
                 int durationMinutes)
{
    if (strlen(flightNumber) > MAX_FLIGHT_NUMBER) {
        fprintf(stderr, "error: flight number '%s' is too long\n",
                flightNumber);
        return NULL;
    }
    
    if (strlen(departureAirport) > MAX_AIRPORT_NAME) {
        fprintf(stderr, "error: departure airport name '%s' is too long\n",
                departureAirport);
        return NULL;
    }
    
    if (strlen(arrivalAirport) > MAX_AIRPORT_NAME) {
        fprintf(stderr, "error: arrival airport name '%s' is too long\n",
                arrivalAirport);
        return NULL;
    }

    if (departureDay < 0 || departureDay > 6) {
        fprintf(stderr, "error: invalid departure day '%d'\n",
                departureDay);
        return NULL;
    }

    if (departureHour < 0 || departureHour > 23) {
        fprintf(stderr, "error: invalid departure hour '%d'\n",
                departureHour);
        return NULL;
    }
    
    if (departureMinute < 0 || departureMinute > 59) {
        fprintf(stderr, "error: invalid departure minute '%d'\n",
                departureMinute);
        return NULL;
    }

    if (durationMinutes < 0) {
        fprintf(stderr, "error: invalid duration '%d'\n",
                durationMinutes);
        return NULL;
    }

    Record r = malloc(sizeof(*r));
    if (r == NULL) {
        fprintf(stderr, "error: out of memory\n");
        exit(EXIT_FAILURE);
    }

    strcpy(r->flightNumber, flightNumber);
    strcpy(r->departureAirport, departureAirport);
    strcpy(r->arrivalAirport, arrivalAirport);
    r->departureDay = departureDay;
    r->departureHour = departureHour;
    r->departureMinute = departureMinute;
    r->durationMinutes = durationMinutes;

    return r;
}

void RecordFree(Record r) {
    free(r);
}

int RecordGetDepartureDay(Record r) {
    return r->departureDay;
}

int RecordGetDepartureHour(Record r) {
    return r->departureHour;
}

int RecordGetDepartureMinute(Record r) {
    return r->departureMinute;
}

int RecordGetDurationMinutes(Record r) {
    return r->durationMinutes;
}

char *RecordGetFlightNumber(Record r) {
    return &(r->flightNumber[0]);
}

char *RecordGetDepartureAirport(Record r) {
    return &(r->departureAirport[0]);
}

char *RecordGetArrivalAirport(Record r) {
    return &(r->arrivalAirport[0]);
}

void RecordShow(Record r) {
	// implement this if you want to debug (optional)
	printf("%s|%s|%s|%s %02d%02d|%d",
	       r->flightNumber, r->departureAirport, r->arrivalAirport,
	       dayToName(r->departureDay), r->departureHour,
	       r->departureMinute, r->durationMinutes);
}

static char *dayToName(int day) {
    assert(day >= 0 && day <= 6);
    
    char *days[] = {
        "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday", "Sunday"
    };
    
    return days[day];
}

