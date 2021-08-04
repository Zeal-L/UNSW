#include <stdio.h>
#include <stdint.h>

void factorial(int n);

int main(void) {
	int n;
    printf("Enter n: ");
	scanf("%d", &n);
	factorial(n);
	return 0;
}

void factorial(int n) {
	int len = 1;            //定义结果长度变量
	uint16_t a[10000] = {0}; //定义结果数组
	a[0] = 1;               //初始结果为1

	for (int i = 2; i <= n; i++) {          //循环n次，求n的阶乘
		int carry = 0;                      //使每次进位数为零
		for (int j = 0; j < len; j++) {     //保存每一位数字并判断结果是否需要增长
			int temp = a[j] * i + carry;    //计算中间结果
			a[j] = temp % 10;               //保存每一位数字，从后往前
			carry = temp / 10;              //计算进位数
			if (j >= len-1 && carry > 0) len++;   //判断结果是否需要增长
		}
	}

    printf("%d! = ",n);
	for (int i = len-1; i >= 0; i--) {
		printf("%d",a[i]);
	}
    putchar('\n');
}