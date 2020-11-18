// COMP1511 Week 7 Test: Interject
//
// Zeal L (abc982210694@gmail.com)
// 2020-10-30 18:27:20
// Week 7 in COMP1511
// Zid:z5325156
//
// This program adds interjections to strings.

#include <stdio.h>
#include <string.h>
#define MAX_SIZE 1002

// Modify str so that it contains interject at the given index.
void interject(char *str, char *interject, int index) {
    // TODO: complete this function.

    char temp_str[MAX_SIZE] = {0};
    for (int i = 0; i < index; i++) {
        temp_str[i] = str[i];
    }
    for (int i = 0; interject[i] != '\0'; i++) {
        temp_str[index + i] = interject[i];
    }
    for (int i = index; str[i] != '\0'; i++) {
        temp_str[strlen(interject) + i] = str[i];
    }
    
    strcpy(str, temp_str);

    // fputs(temp_str, stdout);
    // printf("\n");
}


// This is a simple main function that you can use to test your interject
// function.
// It will not be marked - only your interject function will be marked.
//
// Note: the autotest does not call this main function!
// It calls your interject function directly.
// Any changes that you make to this function will not affect the autotests.

int main(void) {
    char str1[MAX_SIZE] = "Comp Science";
    printf("%s -> ", str1);
    interject(str1, "uter", 4);
    printf("%s\n", str1);

    char str2[MAX_SIZE] = "Beginnings";
    printf("%s -> ", str2);
    interject(str2, "New ", 0);
    printf("%s\n", str2);

    char str3[MAX_SIZE] = "The End!";
    printf("%s -> ", str3);
    interject(str3, " Is Nigh", 7);
    printf("%s\n", str3);

    char str4[MAX_SIZE] = "UNSW Other Unis";
    printf("%s -> ", str4);
    interject(str4, "> ", 5);
    printf("%s\n", str4);

    return 0;
}
