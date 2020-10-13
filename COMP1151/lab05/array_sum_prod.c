// Zeal L (abc982210694@gmail.com)
// 2020-10-13 17:03:34
// Fifth week in COMP1511
// Zid:z5325156

// COMP1511 Array Sum Product
// Calculate the sum and the product of the elements in an array
// and write the results into variables passed into the function
// by reference.

#include <stdio.h>

void array_sum_prod(int length, int nums[length], int *sum, int *product);

// This is a simple main function that you can use to test your array_sum_prod
// function.
// It will not be marked - only your array_sum_prod function will be marked.
//
// Note: the autotest does not call this main function!
// It calls your array_sum_prod function directly.
// Any changes that you make to this main function will not affect the autotests.

int main(void) {
    int nums[] = {3, 4, 1, 5, 6, 1};
    int prod;
    int sum;

    //Pass in the address of the sum and product variables
    array_sum_prod(6, nums, &sum, &prod);

    printf("Sum: %d, Product: %d\n", sum, prod);
    
    int nums2[] = {1, 2, 3, 4};

    //Pass in the address of the sum and product variables
    array_sum_prod(4, nums2, &sum, &prod);

    printf("Sum: %d, Product: %d\n", sum, prod);
    
    return 0;
}


// Calculates the sum and product of the array nums.
// Actually modifies the  variables that *sum and *product are pointing to
void array_sum_prod(int length, int nums[length], int *sum, int *product) {
    int i = 0;
    int temp_sum = 0;
    int temp_product = 1;
    while (i < length) {
        temp_sum += nums[i];
        temp_product *= nums[i];
        i++;
    }
    *sum = temp_sum;
    *product = temp_product;
}
