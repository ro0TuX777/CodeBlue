#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// A simple function with a buffer overflow vulnerability
void vulnerable_function(char *input) {
    char buffer[10];
    strcpy(buffer, input); // Buffer overflow vulnerability
    printf("Input: %s\n", buffer);
}

// A function with a format string vulnerability
void format_string_vulnerable(char *input) {
    printf(input); // Format string vulnerability
}

// A function with an integer overflow vulnerability
void integer_overflow(int a, int b) {
    int result = a + b;
    if (result < 0) {
        printf("Integer overflow detected!\n");
    } else {
        printf("Result: %d\n", result);
    }
}

// A function with a use-after-free vulnerability
void use_after_free() {
    char *ptr = (char *)malloc(10);
    strcpy(ptr, "test");
    printf("Before free: %s\n", ptr);
    free(ptr);
    printf("After free: %s\n", ptr); // Use after free vulnerability
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    printf("Running vulnerable functions...\n");
    
    // Call vulnerable functions
    vulnerable_function(argv[1]);
    format_string_vulnerable(argv[1]);
    integer_overflow(2147483647, 1); // INT_MAX + 1
    use_after_free();

    return 0;
}
