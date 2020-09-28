// By Zeal L, September 2020 Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    char month[12][10] = {"January", "February", "March", "April", 
    "May", "June", "July", "August", "September", "October", 
    "November", "December"};
    int year = 0;
    printf("Enter year: ");
    scanf("%d", &year);
    int a = year % 19;
    int b = year / 100;
    int c = year % 100;
    int d = b / 4;
    int e = b % 4;
    int f = (b+8) / 25;
    int g = (b-f+1) / 3;
    int h = (19*a+b-d-g+15) % 30;
    int i = c / 4;
    int k = c % 4;
    int l = (32+2*e+2*i-h-k) % 7;
    int m = (a+11*h+22*l) / 451;
    int easterMonth = (h+l-7*m+114) / 31;  //3 = March, 4 = April
    int p = (h+l-7*m+114) % 31;
    int easterDate = p + 1;  //date in Easter Month
    printf("Easter is %s %d in %d.\n", month[easterMonth - 1], easterDate, year);
    return 0;
}