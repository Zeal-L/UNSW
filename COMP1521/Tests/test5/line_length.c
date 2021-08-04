// read a line and print its length
#include <stdio.h>

// line of input stored here
char line[256];

int main(void) {
    printf("Enter a line of input: ");
    fgets(line, 256, stdin);

    int i = 0;
    while (line[i] != 0) {
        i++;
    }

    printf("Line length: ");
    printf("%d", i);

    printf("%c", '\n');
    return 0;
}
