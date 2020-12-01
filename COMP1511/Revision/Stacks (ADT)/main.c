// Zeal L (abc982210694@gmail.com)
// 2020-11-29 19:00:29
// Zid: z5325156
// 

#include <stdio.h>
#include <stdlib.h>
#include "stack.h"


int main(void) {
    
    Stack s = stackCreate();
    push('a', s);
    push('b', s);
    push('c', s);
    push('d', s);

    printf("现在顶端的字符是%c\n", peek(s));

    printf("弹出%c, 还剩下%d个字符\n", pop(s), getSize(s)-1);
    printf("弹出%c, 还剩下%d个字符\n", pop(s), getSize(s)-1);
    printf("弹出%c, 还剩下%d个字符\n", pop(s), getSize(s)-1);
    printf("弹出%c, 还剩下%d个字符\n", pop(s), getSize(s)-1);

    stackFree(s);
    
    return EXIT_SUCCESS;
}