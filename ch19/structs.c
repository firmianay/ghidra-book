#include <stdio.h>

struct s1 {
	int a;
	int b;
	int c;
};

typedef struct s2 {
	int x;
	char y;
	float z;
} s2_type;

struct s1 GLOBAL_S1;
s2_type GLOBAL_S2;


void display_s1(struct s1* s) {
	printf("The fields in s1 = %d, %d, and %d\n", s->a, s->b, s->c);
}

void update_s2(s2_type* s, int v) {
	s->x = v;
	s->y = (char)('A' + v);
	s->z = v * 2.0;
}

void do_struct_demo() {
	s2_type local_s2;
	struct s1 local_s1;

	printf("Enter six ints: ");
	scanf("%d %d %d %d %d %d", (int *)&local_s1, &local_s1.b, &local_s1.c,
		  &GLOBAL_S1.a, &GLOBAL_S1.b, &GLOBAL_S1.c);

	printf("You entered: %d and %d\n", local_s1.a, GLOBAL_S1.a);
	display_s1(&local_s1);
	display_s1(&GLOBAL_S1);

	update_s2(&local_s2, local_s1.a);

}

int main() {
	do_struct_demo();
	return 0;
}

