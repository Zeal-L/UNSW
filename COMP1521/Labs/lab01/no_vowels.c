#include <stdio.h>
#include <string.h>


int main(void) {

	char a = '\0';

	while (scanf("%c", &a) != EOF) {
		switch (a) {
		case 'a':	break;
		case 'A':	break;
		case 'e':	break;
		case 'E':	break;
		case 'i':	break;
		case 'I':	break;
		case 'o':	break;
		case 'O':	break;
		case 'u':	break;
		case 'U':	break;
		default:
			printf("%c", a);
			break;
		}
	}

	// // 读到'\n'结束读取,存入a,再抛弃一个字符, 这样就不会把回车扔在缓冲区了
	// while (scanf("%[^\n]%*c", a) != EOF) {
	// 	removeV(a, b);
	// 	printf("%s\n", b);
	// 	memset(b, '\0', MAX);
	// }
	
	return 0;
}
