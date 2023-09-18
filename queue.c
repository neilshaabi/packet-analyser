#include "queue.h"

#include <stdio.h>
#include <stdlib.h>


/**
 * @brief Returns a pointer to a queue struct after allocating memory 
 * for it and initialising each of its fields.
 * 
 * @return struct queue* Pointer to queue struct
 */
struct queue* initialise_queue() {
    
    // Allocate memory for queue
    struct queue* queue = (struct queue*) malloc(sizeof(struct queue));
    if (queue == NULL) {
        fprintf(stderr, "Unable to allocate memory for queue\n");
        exit(1);
    }

    // Initialise size and pointers to first and last elements
    queue->size = 0;
    queue->first = NULL;
    queue->last = NULL;

    return queue;
}


/**
 * @brief Frees memory allocated to each node in the queue as well 
 * as the queue itself.
 * 
 * @param queue Pointer to queue to free
 */
void free_queue(struct queue* queue) {

    // Continue dequeing and freeing each node until queue is empty
    while (is_empty(queue) == 0) {
        struct node* node = dequeue(queue);
        free((void*) node->packet);
        free(node);
    }

    // Free memory allocated to queue itself
    free(queue);
}


/**
 * @brief Returns whether a given queue is empty.
 *
 * @param queue Pointer to queue to check
 * @return int 1 if the queue is empty, 0 otherwise
 */
int is_empty(struct queue* queue) {
    return (queue->first == NULL);
}


/**
 * @brief Inserts a given packet at the back of the queue.
 * 
 * @param queue Pointer to queue in which to insert
 * @param packet Packet to insert into queue
 */
void enqueue(struct queue* queue, struct packet* packet) { 

    // Create new node to store packet
    struct node* new = (struct node*) malloc(sizeof(struct node));
    new->packet = packet;
    new->next = NULL;

    // Update pointers to first and last elements of queue
    if (is_empty(queue) == 1) {
        queue->first = new;
    } else { 
        queue->last->next = new;
    }
    queue->last = new;

    // Increment variable tracking size of queue
    queue->size++;
}


/**
 * @brief Removes and returns the packet at the front of the given queue.
 *
 * @param queue Pointer to queue from which to remove
 * @return struct node* Packet removed from the front of the queue
 */
struct node* dequeue(struct queue* queue) { 

    // Ensure queue is not already empty
    if (is_empty(queue) == 1) {
        fprintf(stderr, "Unable to dequeue items from an empty queue\n");
        exit(1);
    }

    // Update first pointer
    struct node* node = queue->first; 
    queue->first = queue->first->next;  

    // Update last pointer if queue is now empty
    if (queue->first == NULL) {
        queue->last = NULL;  
    }

    // Decrement variable tracking size of queue
    queue->size--;

    return node;
}
