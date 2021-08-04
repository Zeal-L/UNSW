#include <stdio.h>
#include <stdlib.h>

void cc(int n);

int main(int argc, char **argv) {
	
	cc(atoi(argv[1]));
	return EXIT_SUCCESS;
}

void cc(int n) {
	if (n == 1) {
		printf("%d\n", n);
		return;
	} else if (n % 2 != 0) {
		printf("%d\n", n);
		n = n * 3 + 1;
	} else {
		printf("%d\n", n);
		n = n / 2;
	}
	cc(n);
}
