// COMP1521 20T3 final exam Q9 C reference

#include <stdio.h>

void sort(int n, int a[]);
int partition(int n, int a[]);
void swap(int *x, int *y);
void read_array(int n, int a[n]);
void print_array(int n, int a[n]);

int main(void) {
    int size;
    scanf("%d", &size);
    int array[size];
    read_array(size, array);
    sort(size, array);
    print_array(size, array);
}

void sort(int n, int a[]) {
    if (n > 1) {
        int p = partition(n, a);
        sort(p, a);
        sort(n - (p + 1), a + p + 1);
    }
}

int partition(int n, int a[]) {
    int pivot_value = a[n - 1];
    int i = 0;
    for (int j = 0; j < n; j++) {
        if (a[j] < pivot_value) {
            swap(&a[i], &a[j]);
            i = i + 1;
        }
    }
    swap(&a[i], &a[n - 1]);
    return i;
}

void swap(int *x, int *y) {
    int temp = *x;
    *x = *y;
    *y = temp;
}

void read_array(int n, int a[]) {
    for (int i = 0; i < n; i++) {
        scanf("%d", &a[i]);
    }
}

void print_array(int n, int a[]) {
    for (int i = 0; i < n; i++) {
        printf("%d ", a[i]);
    }
    printf("\n");
}
