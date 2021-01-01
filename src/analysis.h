#ifndef IDS_ANALYSIS_H
#define IDS_ANALYSIS_H

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>

void analyse(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);

void setup_variables();
void print_report();

void handle_ip(const unsigned char *link_payload, int verbose);
void handle_tcp(const unsigned char *network_payload, int verbose, uint32_t saddr);
void handle_arp(const unsigned char *link_payload, int verbose);
void handle_http(const unsigned char *transport_payload, int verbose);

void check_unique_ip(int ip_address);

void print_ip_header(struct iphdr *ip_header);
void print_arp_packet(struct ether_arp *ether_arp_packet);
void print_tcp_header(struct tcphdr *tcp_header);

#endif
