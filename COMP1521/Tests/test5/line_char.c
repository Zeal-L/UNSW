//  read a line from stdin and and then an integer n
//  Print the character in the nth-position

#include <stdio.h>

// line of input stored here
char line[256];

int main(void) {

    printf("Enter a line of input: ");
    fgets(line, 256, stdin);

    printf("Enter a position: ");
    int n;
    scanf("%d", &n);

    printf("Character is: ");
    printf("%c", line[n]);
    printf("%c", '\n');

    return 0;
}
