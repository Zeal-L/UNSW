// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>
//Perfect number:
// 1……6
// 2……28
// 3……496
// 4……8128
// 5……33550336
// 6……8589869056

int main(void){
    int number, counter = 1, sum = 0;
    printf("Enter number: ");
    scanf("%d", &number);
    printf("The factors of %d are:\n", number);
    while (number + 1 != counter) {
        if (number % counter == 0) {
            printf("%d\n", counter);
            sum = sum + counter;
        }
        counter++;
    }
    printf("Sum of factors = %d\n", sum);
    if (sum == number*2) {
        printf("%d is a perfect number\n", number);
    } else {
        printf("%d is not a perfect number\n", number);
    }
    return 0;
}