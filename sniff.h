#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

#include <sys/types.h>
#include <pcap.h>

#define BUFSIZE 4096

// Struct storing the number of attacks/violations detected
struct attack_counts {
    unsigned long arp_responses;
    unsigned long syn_packets;
    unsigned long google;
    unsigned long facebook;
};

// Global flags and packet counter
extern int verbose_enabled;
extern int program_running;
extern unsigned long packet_count;

// Structs to store attack attack_counts and IP addresses of SYN packets
extern struct attack_counts* attacks;
extern struct dynamic_array ip_addresses;

// Function prototypes
void sniff(char* interface, int verbose);
void initialise_attack_counts();
void signal_handler(int signal);
void print_summary();
void clean();

#endif
