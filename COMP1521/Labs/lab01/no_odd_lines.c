#include <stdio.h>
#include <string.h>
#define MAX 1024
int main(void) {
	char a[MAX];
	while (fgets(a, MAX, stdin)) {
		if (strlen(a) % 2 == 0) {
			fputs(a, stdout);
		}
	}
	return 0;
}
