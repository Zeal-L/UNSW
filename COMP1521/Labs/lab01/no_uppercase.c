#include <stdio.h>
#include <ctype.h>

int main(void) {
	int a;
	while ((a = getchar()) != EOF) {
		if (a >= 'A' && a <= 'Z') a += 32;
		printf("%c", a);
	}
	return 0;
}
