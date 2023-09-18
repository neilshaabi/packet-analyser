#include "sniff.h"
#include "dispatch.h"
#include "dynamic_array.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pcap.h>
#include <netinet/if_ether.h>

// Global flags and packet counter
int program_running = 1;
int verbose_enabled;              
unsigned long packet_count = 0;

// Global structs and pcap handle
struct attack_counts* attacks;
struct dynamic_array ip_addresses;
pcap_t* pcap_handle;


/**
 * @brief Application main sniffing loop.
 * 
 * @param interface Network interface being listened to
 * @param verbose Verbose flag (0/1)
 */
void sniff(char* interface, int verbose) {

    // Update verbose flag
    verbose_enabled = verbose;
    
    // Install signal handler
    if (signal(SIGINT, signal_handler) == SIG_ERR) {
        printf("Unable to install signal handler");
        exit(1);
    };
    
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the specified network interface for packet capture
    pcap_handle = pcap_open_live(interface, BUFSIZE, 1, 1000, errbuf);

    // Ensure interface has been opened
    if (pcap_handle == NULL) {
        fprintf(stderr, "Unable to open interface %s\n", errbuf);
        exit(EXIT_FAILURE);
    } else {
        printf("SUCCESS! Opened %s for capture\n", interface);
    }

    // Initialise global structs and threadpool
    initialise_attack_counts();
    initialise_array(&ip_addresses);
    initialise_threadpool();
    
    // When pcap loop stops capturing packets
    if (pcap_loop(pcap_handle, -1, dispatch, NULL) < 0) {

        // Clean resources and exit program
        if (program_running == 0) { // pcap loop broken when ctrl+c pressed
            print_summary();
            clean();
            exit(0);
        } else { // pcap loop broken due to error
            fprintf(stderr, "Unable to capture packets");
            clean();
            exit(1);
        }
    }
}


/**
 * @brief Initialises the global attack_counts struct 
 * by setting the value of each field to 0.
 *
 */
void initialise_attack_counts() {

    // Allocate memory for attack counter struct
    attacks = (struct attack_counts*) malloc(sizeof(struct attack_counts));
    if (attacks == NULL) {
        fprintf(stderr, "Unable to allocate memory for attack counters\n");
        exit(1);
    }

    // Set each individual count to 0
    attacks->syn_packets = 0;
    attacks->arp_responses = 0;
    attacks->google = 0;
    attacks->facebook = 0;
}


/**
 * @brief Handles receipt of an interrupt signal (SIGINT), updating the 
 * program_running flag to commence the cleanup process and breaking the 
 * pcap loop to cease packet sniffing.
 *
 * @param signal The signal received represented as an integer.
 */
void signal_handler(int signal) {
  
    // If interrupt signal received (ctrl+c pressed)
    if (signal == SIGINT) {
        program_running = 0;

        // Break pcap loop to cease packet sniffing
        if (pcap_handle) {
            pcap_breakloop(pcap_handle);
        }
    }
}


/**
 * @brief Displays the intrusion detection report consisting of the number
 * of different attacks/violations detected.
 * 
 */
void print_summary() {
    printf("\nIntrusion Detection Report:\n");
    printf("%ld SYN packets detected from %ld different IPs (syn attack)\n", 
        attacks->syn_packets,
        ip_addresses.size
    );
    printf("%ld ARP responses (cache poisoning)\n", 
        attacks->arp_responses
    );
    printf("%ld Blacklist violations (%ld google and %ld facebook)\n",
        attacks->google + attacks->facebook,
        attacks->google,
        attacks->facebook
    );
}


/**
 * @brief Handles the closing of the network interface, cleaning
 * up of the threads and freeing memory allocated to structs.
 * 
 */
void clean() {
  
    // Close network interface
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }

    // Free memory allocated to structs and join threads
    clean_threadpool();
    free(attacks);
    free_array(&ip_addresses);
}
