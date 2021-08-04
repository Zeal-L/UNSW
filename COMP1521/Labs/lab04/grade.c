// read a mark and print the corresponding UNSW grade

#include <stdio.h>

int main(void) {
    int mark;

    printf("Enter a mark: ");
    scanf("%d", &mark);

    if (mark < 50) {
        printf("FL\n");
    } else if (mark < 65) {
        printf("PS\n");
    } else if (mark < 75) {
        printf("CR\n");
    } else if (mark < 85) {
        printf("DN\n");
    } else {
        printf("HD\n");
    }

    return 0;
}
