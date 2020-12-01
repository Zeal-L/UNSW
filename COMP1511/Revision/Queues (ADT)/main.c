// Zeal L (abc982210694@gmail.com)
// 2020-11-29 21:08:57
// Zid: z5325156
// 

// Zeal L (abc982210694@gmail.com)
// 2020-11-29 19:00:29
// Zid: z5325156
// 

#include <stdio.h>
#include <stdlib.h>
#include "queue.h"


int main(void) {
    
    Queue q = queueCreate();
    enqueue(q, 'a');
    enqueue(q, 'b');
    enqueue(q, 'c');

    printf("%c\n", peek(q));
    printf("%d\n", getSize(q));

    dequeue(q);
    dequeue(q);

    show(q);

    queueFree(q);
    
    return EXIT_SUCCESS;
}