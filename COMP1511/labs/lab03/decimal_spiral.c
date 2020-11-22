// Zeal L (abc982210694@gmail.com), September 2020  
// Third week in COMP1511
// Zid:z5325156
#include <stdio.h>

int decimal(int size, int length, int row, int col);

int main(void){
    
    int size, row, col;
    printf("Enter size: ");
    scanf("%d", &size);
    
    //Get the total length of the spiral number
    int length = size * 2;
    int s = size - 2;
    while(s >= 2) {
        length += 2 * s;
        s -= 2;
    }
    length ++;
    //assuming the spiral starts at 0
    //from the outside in, the digit should be
    //(length - posSpiral) % 10 
    //print the grid
    //for each coordinate value, we will check 
    //if it lies on the spiral
    //and if it does, how far along the spiral it is 


    //print the top half
    for (row = 1; row <= size/2+1; row++) {
        for (col = 1; col <= size; col++) {
            if (col <= size - row + 1 && row%2 != 0 && col >= row-2) {
                printf("%d", decimal(size, length, row, col));
            } else if (col <= size - row + 1 && row%2==0 && col >= row -2) {
                printf("-");
            } else if (col%2 != 0) {
                printf("%d", decimal(size, length, row, col));
            } else {
                printf("-");
            }
        }
        printf("\n"); 
    }

    //print lower half
    for(row = size/2+2; row <= size; row++){
        for(col = 1; col <= size; col++) {
            if (col>=size-row+1 && row%2!=0 && col<=row-1) {
                printf("%d", decimal(size, length, row, col));
            } else if (col>=size -row +1 && row%2==0 && col <= row -1) {
                printf("-");
            } else if (col%2!=0) {
                printf("%d", decimal(size, length, row, col));
            } else{
                printf("-");
            }
        }
        printf("\n"); 
    }
}


int decimal (int size, int length, int row, int col) {

    int x = 1, y = 1;
    int travelledTotal = 0 ;
    int curSide = size;
    int curTravelled = 0;
    int direction = 0;
    int sideTime = 0;
    int secondTime = 0;

    //x and y give the position of the coordinate 
    while ((x != row) || (y != col)) {
        curTravelled += 1;
        if (curTravelled < curSide ) {
            if (direction%4 == 0) {
                y += 1;
                travelledTotal += 1;
            } else if (direction%4 == 1) {
                x += 1;
                travelledTotal += 1;
            } else if (direction%4 == 2) {
                y -= 1;
                travelledTotal += 1;
            } else if (direction%4 == 3) {
                x -= 1;
                travelledTotal += 1;
            }
        } else if(curTravelled == curSide){
            //change direction
            direction ++;
            curTravelled = 0;
            if (curSide == size) {
                sideTime ++;
                if (sideTime == 3){
                    curSide -= 2;
                }
            } else if (secondTime) {
                curSide -= 2;
                secondTime = 0;
            } else {
                secondTime = 1;
            }
        }
    }
    return (length - travelledTotal - 1)%10;
}