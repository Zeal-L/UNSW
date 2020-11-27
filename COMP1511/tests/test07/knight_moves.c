// Zeal L (abc982210694@gmail.com)
// 2020-11-18 16:52:42
// Tenth week in COMP1511
// Zid:z5325156

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define LEN 8

void set_board(char *board[LEN][LEN]);

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 0;
    }
    char *start = argv[1];
    char *end = argv[2];
    // i.e. a8 -> 0,7    b5 -> 1,4
    int star_row = start[0] - 97;
    int star_col = start[1] - 49;
    int end_row = end[0] - 96;
    int end_col = end[1] - 48;
    
    char *board[LEN][LEN] = {0}; 
    set_board(board);
    
    return 0;
}

void set_board(char *board[LEN][LEN]) {
    for (int row = 0; row < LEN; row++) {
        for (int col = 0; col < LEN; col++) {
            char index[3];
            index[0] = 'a' + col;
            index[1] = '8' - row; 
            index[2] = '\0'; 
            board[row][col] = index;
            printf("%s ", board[row][col]);
        }
        printf("\n");
    }
}

// #include <stdio.h>
// #include <stdlib.h> 
// //注意，为方便数组访问，纵向为x轴，横向为y轴
// struct node{
// 	int x;//x坐标
// 	int y;//y坐标
// 	int len;//步数
// };
// #define LEN 8
// typedef struct node *Node;

// int main() {
	
//     //使用calloc动态分配时已初始化为0，方便
//     int **mark = (int **)calloc((LEN+1),sizeof(int *));
//     for(int i = 0;i < LEN + 1;i ++) {
//         mark[i] = (int *)calloc((LEN+1),sizeof(int));
//     }//创建标记数组，记录哪些点已经访问过，1代表已访问，0代表未访问
    
//     int a,b,c,d;
//     scanf("%d %d %d %d",&a,&b,&c,&d);//输入坐标
//     mark[a][b] = 1;//将起点标记为访问过
    
//     int move_x[] = {-2,-1,1,2,2,1,-1,-2};
//     int move_y[] = {1,2,2,1,-1,-2,-2,-1};
//     //以上两个数组是对应每个点按照马字走法对应的x，y坐标的变化
//     //比方说index（数组索引）为0时，代表(x-2,y+1)。
//     Node queue = (Node)calloc(LEN*LEN+1,sizeof(struct node));//创建队列
    
//     int head = 0,tail = 1;//head指向队列头，tail指向队列尾
//     //这里不打算用queue[0],纯属个人习惯
//     queue[1].x = a;
//     queue[1].y = b;
//     queue[1].len = 0;//让起点坐标入队列，由于马未开始动，步数为0
    
//     int tag = 0;//标记是否走得到的变量
    
//     while (head <= tail) {//队列非空时 

//         head++;//取出头结点使用,然后头结点出队
        
//         for (int i = 0; i < 8; i++) { //此处是为了遍历8个方向，即bfs

//             //(queue[head].x + move_x[i] > 0)
//             //横坐标不越界
//             //(queue[head].y + move_y[i] > 0)
//             //纵坐标不越界
//             //(mark[queue[head].x + move_x[i]][queue[head].y + move_y[i]] == 0)
//             //下一个方向所到达的点未访问过
//             if (queue[head].x + move_x[i] > 0 
//                 && queue[head].y + move_y[i] > 0 
//                 && mark[queue[head].x + move_x[i]][queue[head].y + move_y[i]] == 0) {
//             //满足上述三个条件马才可走到下一个方向所到的点

//                 tail++;
                
//                 queue[tail].x = queue[head].x + move_x[i];
                
//                 queue[tail].y = queue[head].y + move_y[i];
//                 //可到达的点入队
                
//                 mark[queue[tail].x][queue[tail].y] = 1;
//                 //再标记当前到达的点为已访问
                
//                 queue[tail].len = queue[head].len + 1;
//                 //这一步是用于计算步数，注意每次8个方向搜索完之后，入队的结点的len值都是一样的，然后下一层搜索再让步数+1
                
//                 if (queue[tail].x == c && queue[tail].y == d) {//如果已经到达目标点
//                     printf("%d\n",queue[tail].len);
//                     //输出最短路径的步数
//                     tag = 1;
//                     //标记已经能够到达目标点
//                     break;
//                     //退出内层循环
//                 }
                
//             }
//         } 
//         if (tag) break;//若找到点，退出外层循环
//     }
//     if (tag == 0) printf("0\n");
//     //若队列已空，tag == 0代表不能到达，按照题意输出0；
    
//     for (int i = 0; i < LEN + 1; i ++) {
//         free(mark[i]);
//     }
//     free(mark);//释放
//     free(queue);//释放
// 	return 0;
// }