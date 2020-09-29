// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int counter = 10; 
    while (counter != -1) { //counts down from 10 until 0
        printf("%d\n", counter);
        counter--; 
    } 
    return 0;
}