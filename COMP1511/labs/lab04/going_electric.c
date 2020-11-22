// By Zeal L, September 2020 fourth week in COMP1511
// Zid:z5325156
// Imperfect version

#include<stdio.h>
#define MAX_STATION 10000
#define START_BATTERY 0
       
int main() {   
    int station_number = 0;
    int stations[MAX_STATION] = {0};
    int number_of_stops = 0;
    int battery_left = START_BATTERY;

    //Record charging station information
    while (station_number < MAX_STATION && scanf("%d", &stations[station_number]) == 1) {
        station_number++;
    }
    //current position <= destination
    for (int cur_pos = 0; cur_pos <= station_number;) {
        //If car have less power left than at the charging station, stop and charge
        if (battery_left < stations[cur_pos] && stations[cur_pos] != 0 && cur_pos +1 != station_number) {
            battery_left += stations[cur_pos];
            number_of_stops++;
        } 
        cur_pos++;
        //Arrive at destination
        if (cur_pos == station_number) {
            printf("%d\n", number_of_stops); 
            return 0;
        //Unable to reach destination
        } else if (battery_left <= 0 && cur_pos != station_number && cur_pos != 0) {
            printf("0\n");
            return 1;
        }
        battery_left--;
    }
}