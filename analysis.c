#include "sniff.h"
#include "dispatch.h"
#include "analysis.h"
#include "dynamic_array.h"

#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


/**
 * @brief Analyses a given packet by using the helper functions corresponding
 * with the ethernet type to update the global counter of attacks detected.
 * 
 * @param header Header of packet to analyse
 * @param packet Remainder of packet to analyse
 */
void analyse(const struct pcap_pkthdr* header, const unsigned char* packet) {

	// Get ether header
	struct ether_header* ether_header = (struct ether_header *) packet;

	// Dump packet data if verbose flag enabled
	if (verbose_enabled == 1) {
		dump(packet, (*header).len);
	}

	// Analyse packet based on ethernet type
	unsigned short ethernet_type = ntohs(ether_header->ether_type);
	if (ethernet_type == ETHERTYPE_IP) {
		detect_syn(packet + ETH_HLEN);
	} else if (ethernet_type == ETHERTYPE_ARP) {
		detect_arp(packet + ETH_HLEN);
	}
}


/**
 * @brief 
 * This function analyzes an IP packet to find out if it is
 * a TCP packet and hence detect SYN and HTTP packets.
 * A SYN packet is detected by checking its header flags is
 * set only to SYN. We also add the source IP of all SYN packets
 * to a dynamic list to be analyzed as per the specification. 
 * 
 * HTTP packets are checked to see if any of the host addresses 
 * were blacklisted domains and the destination port was also 
 * 80.
 * @param packet 
 */

/**
 * @brief Detects potential SYN attacks by analysing a given IP packet, 
 * inspecting the values of each of its header flags and updating the 
 * global attack counter. Passes HTTP packet to helper function to check 
 * for URL blacklist violations.
 * 
 * @param packet Packet to analyse
 */
void detect_syn(const unsigned char* packet) {
	
	// Parse IP header
	struct iphdr* ip_header = (struct iphdr*) packet;

	// Check if protocol is TCP (denoted by integer 6)
	if (ip_header->protocol == 6) {

		// Strip the IP header and parse the TCP header
		const unsigned char* ip = packet + (ip_header->ihl * 4);
		struct tcphdr* tcp_header = (struct tcphdr*) ip;

		// Check if only SYN bit is set to 1 (indicates SYN attack)
		if (tcp_header->syn == 1 && tcp_header->ack == 0 
			&& tcp_header->urg == 0 && tcp_header->psh == 0 
			&& tcp_header->rst == 0 && tcp_header->fin == 0
		) {
			attacks->syn_packets++;
			
			// Add IP address of packet in global array if not already stored
			int new_ip_address = abs(ip_header->saddr);
			if (contains(&ip_addresses, new_ip_address) == 0) {
				insert(&ip_addresses, new_ip_address);
			}
		}

		// If destination port is 80, check HTTP packet for URL blacklist violation
		if (ntohs(tcp_header->dest) == 80) {
			const char* http_packet = (char*) (ip + (tcp_header->doff * 4));
			detect_blacklist_violation(http_packet);
		}
	}
}


/**
 * @brief Searches a HTTP packet containing a GET request for a blacklisted URL, 
 * updating the global counter if one is found.
 * 
 * @param http_packet HTTP packet to analyse
 */
void detect_blacklist_violation(const char* http_packet) {

	// If HTTP request is of type GET
	if (strstr(http_packet, "GET")) {

		// Incremenet corresponding counter if blacklisted URL is found
		if (strstr(http_packet, "www.google.co.uk")) {
			attacks->google++;
		} else if (strstr(http_packet, "www.facebook.com")) {
			attacks->facebook++;
		}
	}
}


/**
 * @brief Detects potential ARP cache poisoning attempts by 
 * parsing an ARP packet and checking for an ARP reply, incrementing
 * the global counter if one is found.
 * 
 * @param packet ARP packet to analyse
 */
void detect_arp(const unsigned char* packet) {

	// Parse ARP packet
	struct ether_arp* arp_packet = (struct ether_arp*) packet;
	struct arphdr* arp_header = (struct arphdr*) &arp_packet->ea_hdr;
	
	// If opcode specifies an ARP reply (denoted by integer 2)
	if (ntohs(arp_header->ar_op) == 2) {
		attacks->arp_responses++;
	}
}


/**
 * @brief Utility/debugging method for printing raw packet data.
 * 
 * @param data Raw packet data to dump
 * @param length Length of packet header
 */
void dump(const unsigned char* data, int length) {
	
	unsigned int i;

	// Decode Packet Header
	struct ether_header* eth_header = (struct ether_header*) data;
	printf("\n\n === PACKET %ld HEADER ===", packet_count);
	printf("\nSource MAC: ");
	
	for (i = 0; i < 6; ++i) {
		printf("%02x", eth_header->ether_shost[i]);
		if (i < 5) {
			printf(":");
		}
	}

	printf("\nDestination MAC: ");
	for (i = 0; i < 6; ++i) {
		printf("%02x", eth_header->ether_dhost[i]);
		if (i < 5) {
			printf(":");
		}
	}

	printf("\nType: %hu\n", eth_header->ether_type);
	printf(" === PACKET %ld DATA == \n", packet_count);
	
	// Decode Packet Data (Skipping over the header)
	int data_bytes = length - ETH_HLEN;
	const unsigned char* payload = data + ETH_HLEN;
	const static int output_sz = 20; // Output this many bytes at a time
	
	while (data_bytes > 0) {
		
		int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
		
		// Print data in raw hexadecimal form
		for (i = 0; i < output_sz; ++i) {
			if (i < output_bytes) {
				printf("%02x ", payload[i]);
			} else {
				printf ("   "); // Maintain padding for partial lines
			}
		}
		printf("| ");

		// Print data in ascii form
		for (i = 0; i < output_bytes; ++i) {
			char byte = payload[i];
		// Byte is in printable ascii range
		if (byte > 31 && byte < 127) {
				printf("%c", byte);
			} else {
				printf(".");
			}
		}
		printf("\n");
		
		payload += output_bytes;
		data_bytes -= output_bytes;
	}
	packet_count++;
}
