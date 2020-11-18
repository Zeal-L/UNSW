#include <stdio.h>
#include <string.h>
#define MAX_LEN 1024


int main(void) {
    
    int order[10] = {4, 3, 2, 0, 1};
    for (int i = 0; i < 2; i++) {
        
        for (int j = 0; j != order[i]+1; j++) {
            printf("%d", j);
        }
        printf("\n");
    }
    
    
}