#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int do_math(int a, int b) {
	// c depends on the rand() return val, and influences d and g
	// d depends on a, b, and c, and infulences f
	// e depends on a and c, and influences g
	// f depends on d (directly) and a, b, and c (indeirectly) and influences nothing.
	// g depends on e (directly), and a and c (indirectly) and influences nothing

	int c, d, e, f, g;
	srand(time(0));

	c = rand();
	printf("c=%d\n", c);

	d = a + b + c;
	printf("d=%d\n", d);

	e = a + c;
	printf("e=%d\n", e);

	f = d * 100;
	printf("f=%d\n", f);

	g = rand() - e;
	printf("g=%d\n", g);

	printf("a=%d, b=%d, c=%d, d=%d, e=%d, f=%d, g=%d\n", a, b, c, d, e, f, g);

	return g;
}


int controller() {
	int a, b, rv;
	printf("Enter two integers: ");
	scanf("%d %d", &a, &b);
	rv = do_math(a, b);
	return rv;
}


int main() {
	int rv = controller();
	printf("main(): rv = %d\n", rv);
}

