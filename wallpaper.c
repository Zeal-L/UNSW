#include <stdio.h>
#include <Windows.h>

int main(void) {
    char *path = "C:\\Users\\Zeal\\Desktop\\lqn6nig98onqirlpzam0fupx.jpg";
	if(SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, path,
        SPIF_SENDCHANGE|SPIF_UPDATEINIFILE)) {
		printf("更换成功!\n");
	} else {
		printf("更换失败\n");
	}
	return 0;
}