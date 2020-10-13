// Zeal L (abc982210694@gmail.com)
// 2020-10-13 17:19:43
// Fifth week in COMP1511
// Zid:z5325156

// copy all of the values in source1 which are also found in source2 into destination
// return the number of elements copied into destination
// #include <stdio.h>

// int common_elements(int length, int source1[length], int source2[length], int destination[length]);

// int main(void) {
//     int length = 5;
//     int source1[5] = {1,2,3,2,1};
//     int source2[5] = {1,2,3,4,5};
//     int destination[5] = {0};

//     printf("length is %d\n", common_elements(length,source1,source2,destination));
//     for (int i = 0; i < 5; i++) {
//         printf("%d\n", destination[i]);
//     }
// }

int common_elements(int length, int source1[length], int source2[length], int destination[length]) {
    // PUT YOUR CODE HERE (you must change the next line!)
    int i = 0, j = 0, k = 0,z = 0;
    while (i < length) {
        j = 0;
        while (j < length) {
            if (source1[i] == source2[j]) {
                if (z == 0) {
                    destination[k] = source1[i];
                    k++;
                    z = 1;
                }
            }
            j++;
        }
        z = 0;
        i++;
    }
    return k;
}

// You may optionally add a main function to test your common_elements function.
// It will not be marked.
// Only your common_elements function will be marked.
