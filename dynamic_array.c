#include "dynamic_array.h"

#include <stdio.h>
#include <stdlib.h>


/**
 * @brief Initialises a given pointer to a dynamic array of by 
 * allocating memory for an array initially of size 100, 
 * and setting its size and capacity fields.
 * 
 * @param arr Pointer to dynamic array to initialise
 */
void initialise_array(struct dynamic_array* arr) {
    
    int initial_capacity = 100;
    
    // Allocate memory for array
    arr->array = (unsigned int*) malloc(sizeof(unsigned int) * initial_capacity);
    if (arr->array == NULL) {
        fprintf(stderr, "Unable to reallocate memory for dynamic array\n");
        free_array(arr);
        exit(1);
    }

    // Initialise size and capacity fields
    arr->size = 0;
    arr->capacity = initial_capacity;
}


/**
 * @brief Frees memory allocated to array struct and resets 
 * its individual fields.
 * 
 * @param arr Pointer to dynamic array to free
 */
void free_array(struct dynamic_array* arr) {
    free(arr->array);
    arr->array = NULL;
    arr->size = 0;
    arr->capacity = 0;
}


/**
 * @brief Inserts a given element into the dynamic array located by the
 * given struct pointer, resizing the array if its capacity has been 
 * reached.
 * 
 * @param arr Pointer to dynamic array in which to insert element
 * @param new_element New element to be inserted
 */
void insert(struct dynamic_array* arr, unsigned int new_element) {

    // If array is already full
    if (arr->size == arr->capacity) {
        
        // Increase capacity of array by a factor of 1.5
        arr->capacity *= 1.5;
        arr->array = (unsigned int*) realloc(arr->array, sizeof(unsigned int) * arr->capacity);
        if (arr->array == NULL) {
            fprintf(stderr, "Unable to reallocate memory for dynamic array\n");
            free_array(arr);
            exit(1);
        }
    }

    // Insert new element at next available index
    arr->array[arr->size++] = new_element;
}


/**
 * @brief Determines whether a given dynamic array contains a given element
 * using linear search (does not assume any ordering).
 * 
 * @param arr Pointer to dynamic array to search
 * @param element Element to search for
 * @return int 1 if the array contains the element, 0 otherwise
 */
int contains(struct dynamic_array* arr, unsigned int element) {
    for (int i = 0; i < arr->size; i++) {
        if (arr->array[i] == element) {
            return 1;
        }
    }
    return 0;
}
