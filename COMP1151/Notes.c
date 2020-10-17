//In the linux terminal we will open or create the file to edit by typing:
// & means open in both window
   // gedit newfile.c &

//Once we’re happy with the code we’ve written, we’ll compile it by typing:
    //dcc newfile.c -o 1

//The -o part tells our compiler to write out a file called "helloWorld" that we can then run by typing:
//The ./ lets us run the program "helloWorld" that is in our current directory
    //./1

//Lists all the files in the current directory
    //ls

//Makes a new directory called directoryName
   // mkdir directoryName

//Changes the current directory
   // cd

//Tells you where you are in the directory structure at the moment
   // pwd
    
//删库跑路
   // sudo rm -rf/*

//提示所有警告信息
    //-Wall

//调试
    //-g,  gdb 1, run/r

//语句 #include "FILE.h" 与 #include <FILE.h> 有所不同：
   // 前者在搜索系统头文件目录之前将先在当前目录中搜索文件‘FILE.h’，
   // 后者只搜索系统头文件而不查看当前目录

// Zeal Liang, September 2020, First week of COMP1511

#include <stdio.h>//#include is a special tag for our compiler
// It asks the compiler to grab another file of code and add it to ours
// In this case, it’s the Standard Input Output Library, allowing us to make text appear on the screen (as well as other things)

// int main (void) {// Demo Program showing output
//     printf("Hello World.\n");
//     return 0;
// }

// #define PI 3.14159265359 //Constants are like variables, only they never change
// #define SPEED_OF_LIGHT 299792458.0
// int main (void) {//Code for Variables
//     int answer = 66;
//     int answer_two = 88;// we can also Declare and Initialise together
//     printf("My number is %d, and %d\n",answer,answer_two);/*%d - where in the output you’d like to put an int.
//     After the comma, you put the name of the variable you want to write. 
//     The variables will match the symbols in the same order as they appear*/
//     int diameter = 5;
//     double pi = 3.14159;
//     printf("Diameter is %d, pi is %lf\n", diameter, pi);/*The %d and %lf are symbols that are part of printf
//     %d stands for “decimal integer”
//     %lf stands for “long floating point number” (a double)*/
//     int input;
//     printf("Please type in a number: ");
//     scanf("%d", &input);/*Reads input from the user in the same format as printf
//     Note the & symbol that tells scanf where the variable is*/
//     printf("Your number is: %d\n", input);
//     return 0;
// }

// int main (void) 
// { 
// //   // using getchar() to read a single character from input
// //     int inputChar;
// //     printf("Please enter a character: ");
// //     inputChar = getchar();
// //     printf("The input %c has the ASCII value %d.\n", inputChar, inputChar);
// //     // using putchar() to write a single character to output
// //     putchar(inputChar);

//     // reading and writing lines of text
//     char line[5];
//     while (fgets(line, 2, stdin) != NULL) {
//         fputs(line, stdout);
//     }
    
//     return 0;
// }

// int main(int argc, char *argv[]) {
//     int i = 1;
//     printf("Well actually %s says there's no such thing as ", argv[0]);
//     while (i < argc) {
//         fputs(argv[i], stdout);
//         printf(" ");
//     i++;
//     }
//     printf("\n");
// }

#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[]) {
    int total = 0;

    int i = 1;
    while (i < argc) {
        //string to long integer, 十进制
        total += strtol(argv[i], NULL, 10);
        i++;
    }
    printf("Total is %d.\n", total);
}


