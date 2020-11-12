#include "list.h"
#include "capture.h"
#include <stdio.h>
#include <string.h>

#define SIZE 10
#define MAX_PRINT 10000

int string_contains(char *haystack, char *needle);

// Test whether print_list works for empty lists.
// NOTE: you do not need to edit this; it is just an example.
void test_print_empty_list(void) {
    printf("Test printing out an empty list: ");

    int num_array[SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    List l = nums_to_list(0, num_array);
    char str[MAX_PRINT];
    CAPTURE(print_list(l), str, MAX_PRINT);

    if (!string_contains(str, "X")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    printf("MEETS SPEC\n");
}

// Test whether print_list works for lists of length 1.
void test_print_one_elem_list(void) {
    printf("Test printing out a list with one element: ");

    int num_array[SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    List l = nums_to_list(1, num_array);
    char str[MAX_PRINT];
    CAPTURE(print_list(l), str, MAX_PRINT);

    if (!string_contains(str, "1 -> X")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }
    
    printf("MEETS SPEC\n");
}

// Test whether print_list works for lists with the same element twice.
void test_print_repeated_elem_list(void) {
    printf("Test printing out a list with a repeated element: ");

    int num_array[SIZE] = {1, 1, 1, 1, 1, 6, 6, 6, 9, 10};
    List l = nums_to_list(9, num_array);
    char str[MAX_PRINT];
    CAPTURE(print_list(l), str, MAX_PRINT);

    if (!string_contains(str, "1 -> 1 -> 1 -> 1 -> 1 -> 6 -> 6 -> 6 -> 9 -> X")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    printf("MEETS SPEC\n");
}

// Test whether print_list works for lists with more than ten elements.
void test_print_ten_elem_list(void) {
    printf("Test printing out a list with ten elements: ");

    int num_array[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    List l = nums_to_list(12, num_array);
    char str[MAX_PRINT];
    CAPTURE(print_list(l), str, MAX_PRINT);

    if (!string_contains(str, "1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 11 -> 12 -> X")) {
        printf("DOES NOT MEET SPEC\n");
        return;
    }

    printf("MEETS SPEC\n");
}

//////////////////////////////////////////////////////////////////////////
// NOTE: DO NOT EDIT BELOW THIS COMMENT!                                //
//////////////////////////////////////////////////////////////////////////

// Find the string 'needle' in 'haystack'
int string_contains(char *haystack, char *needle) {
    return strstr(haystack, needle) != NULL;
}

int main(void) {
    test_print_empty_list();
    test_print_one_elem_list();
    test_print_repeated_elem_list();
    test_print_ten_elem_list();
}
