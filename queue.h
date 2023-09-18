#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H

#include "dispatch.h"

// Struct representing a packet stored in the queue with a 
// pointer to the next node
struct node { 
	struct packet* packet;
	struct node* next;
};

// Struct representing a queue data structure (FIFO)
struct queue { 
  	int size;
  	struct node* first;
  	struct node* last;
};

// Function prototypes
struct queue* initialise_queue();
void free_queue(struct queue* queue);
int is_empty(struct queue* queue);
void enqueue(struct queue* queue, struct packet* packet);
struct node* dequeue(struct queue* queue);

#endif
