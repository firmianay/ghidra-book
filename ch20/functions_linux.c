#include <stdio.h>
#include <stdlib.h>


int maybe_inline() {
	return 0x12abcdef;
}

#ifdef __i386__

#define stdcall __attribute__((stdcall))
#define cdecl __attribute__((cdecl))
#define fastcall __attribute__((fastcall))
#define regparm __attribute__((regparm(2)))

int  cdecl cdecl_example(int a) {
	int b;
	printf("Enter an int: ");
	scanf("%d", &b);
	return a * b;
}

int  stdcall stdcall_example(int a) {
	int b;
	printf("Enter an int: ");
	scanf("%d", &b);
	return a * b;
}

int  fastcall fastcall_example(int a) {
	int b;
	printf("Enter an int: ");
	scanf("%d", &b);
	return a * b;
}

int  regparm regparm_example(int a) {
	int b;
	printf("Enter an int: ");
	scanf("%d", &b);
	return a * b;
}
#endif

int main() {
	int v;
	
	v = maybe_inline();
	printf("after maybe_inline: v = %08x\n", v);

#ifdef __i386__
	v = rand();
	v = cdecl_example(v);
	printf("after cdecl_example: v = %08x\n", v);

	v = rand();
	v = stdcall_example(v);
	printf("after stdcall_example: v = %08x\n", v);

	v = rand();
	v = fastcall_example(v);
	printf("after fastcall_example: v = %08x\n", v);

	v = rand();
	v = regparm_example(v);
	printf("after regparm_example: v = %08x\n", v);
#endif

	return 0;
}

