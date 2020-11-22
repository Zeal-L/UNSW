// By Zeal L, September 2020  Third week in COMP1511
// Zid:z5325156
#include<stdio.h>

int main(void){
    int n1 = 0, n2 = 0, n3 = 0;
    printf("Enter integer: ");
    scanf("%d", &n1);
    printf("Enter integer: ");
    scanf("%d", &n2);
    printf("Enter integer: ");
    scanf("%d", &n3);


    
    printf("The integers in order are: %d %d %d\n", 
        n1 * (n1<=n2 && n1<=n3) + n2 * (n2<n1 && n2<=n3) + n3 * (n3<n2 && n3<n1),
        n1 * ((n1<=n2 && n1>=n3) || (n1>=n2 && n1<=n3)) + n2 * ((n2<n1 && n2>=n3) || (n2>n1 && n2<=n3)) + n3 * ((n3<n2 && n3>n1) || (n3>n2 && n3<n1)), 
        n1 * (n1>=n2 && n1>=n3) + n2 * (n2>n1 && n2>=n3) + n3 * (n3>n2 && n3>n1));
      
    return 0;
}