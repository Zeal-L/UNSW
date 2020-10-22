// Zeal L (abc982210694@gmail.com)
// 2020-10-20 10:13:33
// Sixth week in COMP1511
// Zid:z5325156
//
// COMP1511 Array Print Pointer
// Print out the contents of an array, starting
// from index 0 and ending by printing out
// a particular element that is also being
// pointed at by a given pointer

// Marc Chee, March 2020

#include <stdio.h>

#define LENGTH 10

void array_print_pointer(int nums[LENGTH], int *last);

// This is a simple main function that you can use to 
// test your array_print_pointer function.
// It will not be marked - only your array_print_pointer 
// function will be marked.
//
// Note: the autotest does not call this main function!
// It calls your array_print_pointer function directly.
// Any changes that you make to this main function will 
// not affect the autotests.

int main(int argc, char *argv[]){
    int nums[LENGTH] = {1,2,3,4,5,6,7,8,9,10};
    int *last = &nums[5];

    // Pass in the array and a pointer to the 
    // last element that should be printed
    array_print_pointer(nums, last);

    int nums2[LENGTH] = {1,5,4,3,5,6,7,8,9,10};
    int *last2 = &nums2[8];

    // Pass in the array and a pointer to the 
    // last element that should be printed
    array_print_pointer(nums2, last2);

    // int nums3[LENGTH] = {1,5,4,3,5,6,7,8,9,10};
    // int *last3 = &nums3[2];
    // array_print_pointer(nums3, last3);
    return 0;
}

// Print an array from the beginning until it reaches
// a pointer to one of the elements. That element is
// the last thing printed out.

// Assumes that the pointer is aimed at one of the array elements.
void array_print_pointer(int nums[LENGTH], int *last) {
    for (int i = 0; &nums[i] != last+1; i++) {
        printf("%d ", nums[i]);
    }
}
