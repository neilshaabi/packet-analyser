#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include "analysis.h"
#include "sniff.h"

#include <pcap.h>

// Number of bytes in header
#define ETH_HLEN 14;

// Function prototypes
void analyse(const struct pcap_pkthdr* header, const unsigned char* packet);
void detect_syn(const unsigned char* packet);
void detect_blacklist_violation(const char* http_packet);
void detect_arp(const unsigned char* packet);
void dump(const unsigned char* data, int length);

#endif
