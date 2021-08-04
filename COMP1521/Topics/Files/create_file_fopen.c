// create file "hello.txt" containing 1 line: Hello, Andrew

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {

    FILE *output_stream = fopen("hello.txt", "w");
    if (output_stream == NULL) {
        perror("hello.txt");
        return 1;
    }

    fprintf(output_stream, "Hello, Andrew!\n");

    // fclose will flush data to file
    // best to close file ASAP
    // but doesn't matter as file autoamtically closed on exit
    fclose(output_stream);

    return 0;
}