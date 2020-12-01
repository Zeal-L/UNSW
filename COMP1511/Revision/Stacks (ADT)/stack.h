// Zeal L (abc982210694@gmail.com)
// 2020-11-29 19:00:25
// Zid: z5325156
// 

typedef struct node *Node;
typedef struct stack *Stack;


Stack stackCreate();

void stackFree(Stack s);

void push(char c, Stack s);

char pop(Stack s);

char peek(Stack s);

int getSize(Stack s);