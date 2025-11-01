#include <stdio.h>

// Global variables
int global_var1 = 10;
int global_var2 = 20;
static int static_var = 5;

// Functions
void hello() {
    printf("Hello, world!\n");
}

void add_numbers(int a, int b) {
    int result = a + b;
    printf("%d + %d = %d\n", a, b, result);
}

int multiply_numbers(int x, int y) {
    return x * y;
}

static void secret_function() {
    printf("This is a static function.\n");
}

int main() {
    hello();
    add_numbers(global_var1, global_var2);
    int product = multiply_numbers(global_var1, global_var2);
    printf("Product: %d\n", product);
    secret_function();
    return 0;
}
