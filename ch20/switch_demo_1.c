#include <stdio.h>

/* Switch values are sequential and ordered in the source
 * Ghidra book Listring 19-1
 */
int switch_version_1(int a, int b, int c, int d) {
	int result = 0;

	switch (a) {
		case 1:
			// code executed when value == 1
			result = a + b;
			break;
		case 2:
			// code executed when value == 2
			result = a + c;
			break;
		case 3:
			// code executed when value == 3
			result = a + d;
			break;
		case 4:
			// code executed when value == 4
			result = b + c;
			break;
		case 5:
			// code executed when value == 5
			result = b + d;
			break;
		case 6:
			// code executed when value == 6
			result = c + d;
			break;
		case 7:
			// code executed when value == 7
			result = a - b;
			break;
		case 8:
			// code executed when value == 8
			result = a - c;
			break;
		case 9:
			// code executed when value == 9
			result = a - d;
			break;
		case 10:
			// code executed when value == 10
			result = b - c;
			break;
		case 11:
			// code executed when value == 11
			result = b - d;
			break;
		case 12:
			// code executed when value == 12
			result = c - d;
			break;
	}

	return result;
}

/* Switch values are sequential and ordered in the source (except that 10
   is omited and a new value, 13 is added at the end)
 */
int switch_version_2(int a, int b, int c, int d) {
	int result = 0;

	switch (a) {
		case 1:
			// code executed when value == 1
			result = a + b;
			break;
		case 2:
			// code executed when value == 2
			result = a + c;
			break;
		case 3:
			// code executed when value == 3
			result = a + d;
			break;
		case 4:
			// code executed when value == 4
			result = b + c;
			break;
		case 5:
			// code executed when value == 5
			result = b + d;
			break;
		case 6:
			// code executed when value == 6
			result = c + d;
			break;
		case 7:
			// code executed when value == 7
			result = a - b;
			break;
		case 8:
			// code executed when value == 8
			result = a - c;
			break;
		case 9:
			// code executed when value == 9
			result = a - d;
			break;
		case 11:
			// code executed when value == 11
			result = b - d;
			break;
		case 12:
			// code executed when value == 12
			result = c - d;
			break;
		case 13:
			// code executed when value == 10
			result = b - c;
			break;
	}

	return result;
}

/* Switch values are sequential and NOT ordered in the source
 */
int switch_version_3(int a, int b, int c, int d) {
	int result = 0;

	switch (a) {
		case 9:
			// code executed when value == 9
			result = a - d;
			break;
		case 3:
			// code executed when value == 3
			result = a + d;
			break;
		case 4:
			// code executed when value == 4
			result = b + c;
			break;
		case 11:
			// code executed when value == 11
			result = b - d;
			break;
		case 6:
			// code executed when value == 6
			result = c + d;
			break;
		case 5:
			// code executed when value == 5
			result = b + d;
			break;
		case 1:
			// code executed when value == 1
			result = a + b;
			break;
		case 12:
			// code executed when value == 12
			result = c - d;
			break;
		case 7:
			// code executed when value == 7
			result = a - b;
			break;
		case 8:
			// code executed when value == 8
			result = a - c;
			break;
		case 2:
			// code executed when value == 2
			result = a + c;
			break;
		case 10:
			// code executed when value == 10
			result = b - c;
			break;
	}

	return result;
}

/* Switch values are widely distributed but provided in order in the source
 * Ghidra book listring 19-2
 */
int switch_version_4(int a, int b, int c, int d) {
	int result = 0;

	switch (a) {
		case 1:
			// code executed when value == 1
			result = a + b;
			break;
		case 211:
			// code executed when value == 211
			result = a + c;
			break;
		case 295:
			// code executed when value == 295
			result = a + d;
			break;
		case 462:
			// code executed when value == 462
			result = b + c;
			break;
		case 528:
			// code executed when value == 528
			result = b + d;
			break;
		case 719:
			// code executed when value == 719
			result = c + d;
			break;
		case 995:
			// code executed when value == 995
			result = a - b;
			break;
		case 1024:
			// code executed when value == 1024
			result = a - c;
			break;
		case 8000:
			// code executed when value == 8000
			result = a - d;
			break;
		case 13531:
			// code executed when value == 13531
			result = b - c;
			break;
		case 13532:
			// code executed when value == 13532
			result = b - d;
			break;
		case 15027:
			// code executed when value == 15027
			result = c - d;
			break;
	}

	return result;
}

/* Switch values are widely distributed but NOT provided in order in the source
 */
int switch_version_5(int a, int b, int c, int d) {
	int result = 0;

	switch (a) {
		case 13531:
			// code executed when value == 13531
			result = b - c;
			break;
		case 211:
			// code executed when value == 211
			result = a + c;
			break;
		case 995:
			// code executed when value == 995
			result = a - b;
			break;
		case 462:
			// code executed when value == 462
			result = b + c;
			break;
		case 1:
			// code executed when value == 1
			result = a + b;
			break;
		case 528:
			// code executed when value == 528
			result = b + d;
			break;
		case 719:
			// code executed when value == 719
			result = c + d;
			break;
		case 15027:
			// code executed when value == 15027
			result = c - d;
			break;
		case 1024:
			// code executed when value == 1024
			result = a - c;
			break;
		case 295:
			// code executed when value == 295
			result = a + d;
			break;
		case 8000:
			// code executed when value == 8000
			result = a - d;
			break;
		case 13532:
			// code executed when value == 13532
			result = b - d;
			break;
	}

	return result;
}


/* If values are sequential and ordered in the source
 */
int if_version_1(int a, int b, int c, int d) {
	int result = 0;

	if (a == 1) {
		// code executed when value == 1
		result = a + b;
	} else if (a == 2) {
		// code executed when value == 2
		result = a + c;
	} else if (a == 3) {
		// code executed when value == 3
		result = a + d;
	} else if (a == 4) {
		// code executed when value == 4
		result = b + c;
	} else if (a == 5) {
		// code executed when value == 5
		result = b + d;
	} else if (a == 6) {
		// code executed when value == 6
		result = c + d;
	} else if (a == 7) {
		// code executed when value == 7
		result = a - b;
	} else if (a == 8) {
		// code executed when value == 8
		result = a - c;
	} else if (a == 9) {
		// code executed when value == 9
		result = a - d;
	} else if (a == 10) {
		// code executed when value == 10
		result = b - c;
	} else if (a == 11) {
		// code executed when value == 11
		result = b - d;
	} else if (a == 12) {
		// code executed when value == 12
		result = c - d;
	}

	return result;
}


int main() {
	int a, b, c, d, r;

	printf("Enter 4 integers: ");
	scanf("%d %d %d %d", &a, &b, &c, &d);

	r = switch_version_1(a, b, c, d);
	printf("The result from switch_version_1 was %d\n", r);

	r = switch_version_2(a, b, c, d);
	printf("The result from switch_version_2 was %d\n", r);

	r = switch_version_3(a, b, c, d);
	printf("The result from switch_version_3 was %d\n", r);

	r = switch_version_4(a, b, c, d);
	printf("The result from switch_version_4 was %d\n", r);

	r = switch_version_5(a, b, c, d);
	printf("The result from switch_version_5 was %d\n", r);

	r = if_version_1(a, b, c, d);
	printf("The result from if_version_1 was %d\n", r);

	return 0;
}

