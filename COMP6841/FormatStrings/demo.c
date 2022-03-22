#include <stdio.h>

int main(void){
    char input[100] = {0};
    while (1) {
        printf("Enter input: ");
        gets(input);
        printf(input);
    }
}