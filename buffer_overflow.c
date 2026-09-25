#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// A function with a buffer overflow vulnerability
void vulnerable_function(char *input) {
    char buffer[10];
    // Buffer overflow vulnerability - no bounds checking
    strcpy(buffer, input);
    printf("Input: %s\n", buffer);
}

// A function with a format string vulnerability
void format_string_vulnerable(char *input) {
    // Format string vulnerability - user input used as format string
    printf(input);
}

// A function with an integer overflow vulnerability
void integer_overflow(int a, int b) {
    int result = a + b;
    // Integer overflow vulnerability - no check for overflow
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
    // Use-after-free vulnerability - using memory after it's been freed
    printf("After free: %s\n", ptr);
}

// A function with a stack-based buffer overflow vulnerability
void stack_overflow(int n) {
    // Stack-based buffer overflow - array size determined by user input
    int buffer[10];
    for (int i = 0; i < n; i++) {
        buffer[i] = i;
    }
    for (int i = 0; i < 10; i++) {
        printf("%d ", buffer[i]);
    }
    printf("\n");
}

// A function with a heap overflow vulnerability
void heap_overflow(int size) {
    char *buffer = (char *)malloc(10);
    // Heap overflow vulnerability - writing beyond allocated memory
    for (int i = 0; i < size; i++) {
        buffer[i] = 'A';
    }
    buffer[size] = '\0';
    printf("Heap buffer: %s\n", buffer);
    free(buffer);
}

// A function with a null pointer dereference vulnerability
void null_pointer_dereference(int x) {
    int *ptr = NULL;
    if (x > 10) {
        ptr = &x;
    }
    // Null pointer dereference vulnerability - no check for NULL
    printf("Value: %d\n", *ptr);
}

// A function with a double free vulnerability
void double_free() {
    char *ptr = (char *)malloc(10);
    strcpy(ptr, "test");
    printf("Allocated: %s\n", ptr);
    free(ptr);
    // Double free vulnerability - freeing memory twice
    free(ptr);
}

// A function with an uninitialized variable vulnerability
void uninitialized_variable() {
    int x;
    // Uninitialized variable vulnerability - using x without initialization
    if (x > 0) {
        printf("X is positive: %d\n", x);
    } else {
        printf("X is negative or zero: %d\n", x);
    }
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
    stack_overflow(15); // Overflow the stack buffer
    heap_overflow(20);  // Overflow the heap buffer
    
    // These are commented out to prevent crashes during testing
    // null_pointer_dereference(5);
    // double_free();
    
    uninitialized_variable();

    return 0;
}
