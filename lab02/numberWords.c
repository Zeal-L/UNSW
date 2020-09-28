// By Zeal L, September 2020  Secend week in COMP1511
// Zid:z5325156
#include<stdio.h>
#define MAX 5
#define MIN 1

int main(void){
    char words[10][10] = {"zero", "one", "two", "three", 
    "four", "five", "six", 
    "seven", "eight", "nine"
    };
    printf("Please enter an integer:");
    int number;
    int count = 0;
    scanf("%d", &number);
    if (MIN <= number && number <= MAX) {
        while (count != number) {
            count++;
        }
        printf("You entered %s.\n", words[count]);
    } else if (number < MIN) {
        printf("You entered a number less than one.\n");
    } else if (number > MAX) {
        printf("You entered a number greater than five.\n");
    }
    return 0;
}