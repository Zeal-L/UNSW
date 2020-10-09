// Zeal L (abc982210694@gmail.com), October 2020  
// Fourth week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int sum = 0;
    printf("How many numbers: ");
    int counter = 0;
    int i = 0;
    int number = 0;
    scanf("%d", &counter);
    while (i < counter) {
        scanf("%d", &number);
        sum += number;
        i++;
    }
    printf("The sum is: %d\n", sum);
    return 0;
}