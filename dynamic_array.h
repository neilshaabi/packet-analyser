#ifndef CS241_DYNAMIC_ARRAY_H
#define CS241_DYNAMIC_ARRAY_H

#include <stddef.h>
#include <sys/types.h>

// Struct representing a dynamic (resizable) array
struct dynamic_array {
    unsigned int* array;
    size_t size;
    size_t capacity;
};

// Function prototypes
void initialise_array(struct dynamic_array* arr);
void free_array(struct dynamic_array* a);
void insert(struct dynamic_array* a, unsigned int element);
int contains(struct dynamic_array* arr, unsigned int element);

#endif
