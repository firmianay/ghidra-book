#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int demo_unreachable(volatile int a) {
	volatile int b = a ^ a;
	if (b) {
		printf("This is unreachable\n");
		a += 1;
	}

	if (a - a > 0) {
		printf("This should be unreachable too\n");
		a += 1;
	} else {
		printf("We should always see this\n");
		a += 2;
	}

	printf("End of demo_unreachable()\n");
	return a;
}


long demo_extintops(int a) {
	long l;
	l  = (((long)a) << 32) | (a ^ 0xa5);
	*((unsigned char*)&l) ^ 'A';

	printf("End of demo_extintops()\n");
	return l;
}

int demo_simppred(int a) {
	if (a > 0) {
		printf("A is > 0\n");
	}

	if (a > 0) {
		printf("Yes, A is definately > 0!\n");
	}

	if (a > 2) {
		printf("A > 2\n");
	}

	return a * 10;
}


void do_demos() {
	srand(time(0));
	int a = rand() % 16;

	a += demo_unreachable(a);
	printf("a = %d\n", a);
	long l = demo_extintops(a);
	printf("l = %ld\n", l);
	a += demo_simppred(a);
	printf("a = %d\n", a);
}

int main() {
	do_demos();
	return 0;
}

