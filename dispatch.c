#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"
#include "dynamic_array.h"
#include "queue.h"

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>


// Threadpool and request queue declarations
pthread_t threadpool[THREADPOOL_SIZE];
struct queue* request_queue;

// Initialisations of mutex locks and condition variable for queue
pthread_mutex_t main_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;


/**
 * @brief Callback function provided to pcap_loop (refer to sniff.c). Copies new
 * packets to the heap to prevent memory from being overwritten, then inserts packet 
 * data into separate struct to be added to the request queue for processing by threads.
 * 
 * @param args user arguments provided to pcap_loop
 * @param header Header of new packet
 * @param packet Remainder of new packet
 */
void dispatch(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {

    // Increment global counter for the number of packets sniffed
    packet_count++;

    // Allocate memory to copy packet data to heap
    unsigned char* packet_data = malloc((header->len + 1) * sizeof(char));
    if (packet_data == NULL) {
        fprintf(stderr, "Unable to copy data of new packet to heap\n");
        exit(1);
    }

    // Copy packet data to heap
    memcpy(packet_data, packet, header->len);
    packet_data[(header->len) * sizeof(char)] = '\0';
   
    // Allocate memory to insert new packet and header into a separate struct
    struct packet* pckt = (struct packet*) malloc(sizeof(struct packet));
    if (pckt == NULL) {
        fprintf(stderr, "Unable to allocate memory for new packet\n");
        exit(1);
    }

    // Insert new packet and header into struct
    pckt->data = packet_data;
    pckt->header = header;

    // Add packet to queue and broadcast condition to 'wake up' worker threads
    pthread_mutex_lock(&queue_mutex);
    enqueue(request_queue, pckt);
    pthread_cond_broadcast(&cond_var);
	pthread_mutex_unlock(&queue_mutex);
}


/**
 * @brief Initialises a pool of worker threads by creating a request queue
 * followed by a predefined number of threads.
 * 
 */
void initialise_threadpool() {
    request_queue = initialise_queue();
	for (int i = 0; i < THREADPOOL_SIZE; i++) {
		pthread_create(&threadpool[i], NULL, &thread_code, NULL);
	}
}


/**
 * @brief Freees memory allocated to the request queue and joins threads.
 * 
 */
void clean_threadpool() {

    // Free queue
    pthread_mutex_lock(&queue_mutex);
    free_queue(request_queue);
    pthread_mutex_unlock(&queue_mutex);

    // Join threads
    for (int i = 0; i < THREADPOOL_SIZE; i++) {
        pthread_cond_broadcast(&cond_var);
        pthread_join(threadpool[i], NULL);
    }
}


/**
 * @brief Code exectued by each thread indefinitely until an interrupt signal 
 * is received. Thread waits for a condition variable to be broadcast, then 
 * dequeues a packet from the work queue and analyses it.
 * 
 * @return void* NULL pointer
 */
void* thread_code() {

    while (program_running == 1) {

        pthread_mutex_lock(&queue_mutex);

        // Wait for condition variable to be broadcast while queue is empty
        while ((program_running == 1) && (is_empty(request_queue) == 1)) {  
            pthread_cond_wait(&cond_var, &queue_mutex);
        }

        if (program_running == 0) {
            break;
        }

        // Retrieve new packet from request queue
        struct node* node = dequeue(request_queue);

        pthread_mutex_unlock(&queue_mutex);

        // Pass packet header and data to analyse function
        pthread_mutex_lock(&main_mutex);
        analyse(node->packet->header, node->packet->data);
        pthread_mutex_unlock(&main_mutex);

        // Free memory allocated to node
        free((void*) node->packet->data);
        free(node->packet);
        free(node);
    }
    pthread_mutex_unlock(&queue_mutex);
    return NULL;
}
