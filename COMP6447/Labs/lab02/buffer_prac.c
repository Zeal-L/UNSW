#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>

void win_better() {
    printf("How did you get here??\n");
    system("/bin/sh");
}

void win(){
    printf("WINNNER WINNER CHICKEN DINNER!\n");
}

int guess = 0;

int main(){
	srand(time(NULL));
	char input[10];
	int random = (rand() % (126-32)) + 32;

	printf("Can you guess what number I'm thinking of between 32 - 126?\n");

	fgets(input,10,stdin);
	if(!strchr(input, '\n')){
		while(fgetc(stdin)!='\n');
	}

	guess = atoi(input);
	if (guess != random){
		printf("WRONG!!!\nThe number was: %d\n",random);
		printf("Do you want me to check your answer again? y\\n \n");

		gets(input);

		if(input[0] != 'y'){
			return 0;
		}

		if (guess == random) {
			win();
		}else{
			printf("You still lose...\n");
		}	
	}else{
		win();
		printf("Lucky guess!\nBut can you guess wrong and still win!\n");
	}
}