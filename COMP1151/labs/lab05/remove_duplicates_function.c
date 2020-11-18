// Zeal L (abc982210694@gmail.com)
// 2020-10-15 21:43:27
// Fifth week in COMP1511
// Zid:z5325156

// #include <stdio.h>
// #define LENGTH 6
// int remove_duplicates(int length, int source[length], int destination[length]);

// int main(void){

//     int source[LENGTH] = {3,1,4,1,5,9};
//     int destination[LENGTH] = {0}; 
//     int dest_len = remove_duplicates(LENGTH, source, destination);
//     printf("%d\n", dest_len);
//     int i = 0;
//     while (i < dest_len) {
//         printf("%d ", destination[i]);
//         i++;
//     }
//     printf("\n");
//     return 0;
// }

int remove_duplicates(int length, int source[length], int destination[length]) {

    int dest_len = 0;
    int flag[10000] = {0}; // Make an initial tag for each element
    for (int i = 0; i < length; i++) {
        if (flag[source[i]] == 0) {
            destination[dest_len++] = source[i];
            // Set the tag to 1 if it ever occurs.
            flag[source[i]] = 1;
        }
    }

    return dest_len;
}    