#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

#define THREADPOOL_SIZE 25

// Struct storing the header of a packet and its remaining data
struct packet {
  const struct pcap_pkthdr* header;
  const unsigned char* data;
};

// Function prototypes
void dispatch(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
void initialise_threadpool();
void clean_threadpool();
void* thread_code();

#endif
