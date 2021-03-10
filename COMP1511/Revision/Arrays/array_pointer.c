#include <stdio.h>
#include <stdlib.h>
int main(void) {
    int a[4] = {4, 3, 2, 1};
    int *p, **b;
    p = a;
    b = &p;
    printf("a的地址->%p\n", a);
    printf("a的地址->%p\n", &a);
    printf("a的地址->%p\n", p);
    printf("a的地址->%p\n", *b);
    putchar('\n');
    printf("p的地址->%p\n", &p);
    printf("p的地址->%p\n", b);
    putchar('\n');
    printf("b的地址->%p\n", &b);
    putchar('\n');
    printf("a的第一个值>%d\n", a[0]);
    printf("a的第二个值>%d\n", *(p+1));
    printf("a的第三个值>%d\n", *(*b+2));
    
    return EXIT_SUCCESS;
}