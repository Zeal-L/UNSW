// read a line and print whether it is a palindrom
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
    int j = 0;
    int k = i - 2;
    while (j < k) {
        if (line[j] != line[k]) {
            printf("not palindrome\n");
            return 0;
        }
        j++;
        k--;
    }
    printf("palindrome\n");
    return 0;
}
