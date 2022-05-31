#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
   int x;
   printf("Enter an integer: ");
   scanf("%d", &x);

   printf("%d %% 16 = %d\n", x, x % 16);
   printf("%d %% 10 = %d\n", x, x % 10);
   printf("%d %% 3 = %d\n", x, x % 3);
   printf("%d / 16 = %d\n", x, x / 16);
   printf("%d / 10 = %d\n", x, x / 10);
   printf("%d / 3 = %d\n", x, x / 3);
}

