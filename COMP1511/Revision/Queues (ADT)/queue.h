// Zeal L (abc982210694@gmail.com)
// 2020-11-29 21:09:01
// Zid: z5325156
// 


typedef struct node *Node;
typedef struct queue *Queue;

Queue queueCreate(void);

void queueFree(Queue q);

void enqueue(Queue q, char c);

char dequeue(Queue q);

char peek(Queue q);

int getSize(Queue q);

void show(Queue q);

