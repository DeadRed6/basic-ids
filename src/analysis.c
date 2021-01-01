//This code parses each TCP/IP layer and analyses the header fields of each protocol
#include "analysis.h"
#include "sniff.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

//Initialise metrics which we increment within the different parsing functions
int syn_packet_count = 0;
int syn_unique_ip_count = 0;
int arp_response_count = 0;
int blocklist_violation_count = 0;
int total_packet_count = 0;

//Stores Unique IPs from SYN attacks
int *ip_array_ptr;
int ip_array_size;

//Allocate memory for the dynamically-sized array, start with just 8 IP addresses before resizing
void setup_variables() {
        ip_array_ptr = (int *) malloc(8 * sizeof(int));
        if(ip_array_ptr == NULL) {
                printf("\nError: Could not malloc memory.");
                exit(1);
        }
        ip_array_size = 8;
}

//Called from within the signal handler. Not signal safe.
void print_report() {
        printf("\n\nIntrusion Detection Report: ");
        printf("\n%d SYN packets detected from %d different IPs (SYN Attack)", syn_packet_count, syn_unique_ip_count);
        printf("\n%d ARP responses (cache poisoning)", arp_response_count);
        printf("\n%d URL Blocklist violations", blocklist_violation_count);
        printf("\n%d total packets seen\n", total_packet_count);
		free(ip_array_ptr);
}

//Entry point for program functionality that actually processes the packets
void analyse(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet) {
        total_packet_count++;
        if(signal(SIGINT, sig_handler) == SIG_ERR) printf("\nCouldn't terminate.\n"); //Capture a Ctrl-C input

        struct ether_header *eth_header = (struct ether_header *) packet;
        const unsigned char *link_payload = packet + ETH_HLEN; //Skip over the Ethernet header bytes to get to the payload

        int verbose = (int) user;

        switch((int) ntohs(eth_header->ether_type)) {
                case 2048: handle_ip(link_payload, verbose); //IP Packet
				break;
                case 2054: handle_arp(link_payload, verbose); //ARP Packet
                break;
                default: ; //This other type of packet is not considered.
        }
        if(verbose) printf("\n");
}

//Parses ARP header to check for ARP response packets
void handle_arp(const unsigned char *link_payload, int verbose) {
        struct ether_arp *ether_arp_packet= (struct ether_arp *) link_payload;
        struct arphdr *arp_header = &ether_arp_packet->ea_hdr;
        if(ntohs(arp_header->ar_op) == 2) arp_response_count++;
        if(verbose) print_arp_packet(ether_arp_packet);
}

//Parses IP header to check for TCP packets, otherwise the function terminates
void handle_ip(const unsigned char *link_payload, int verbose) {
        struct iphdr *ip_header = (struct iphdr *) link_payload;
        if(verbose) print_ip_header(ip_header);
        //We only care about TCP packets, but particularly those on port 80.
        if(ip_header->protocol == 6) {
                const unsigned char *network_payload = link_payload + (ip_header->ihl * 4); //Skip over some octets to get to the payload
                handle_tcp(network_payload, verbose, ip_header->saddr);
        }
}

//Checks flags in the TCP header and then checks for HTTP packets
//Takes in the source IP address as it is needed for detecting unqiue IP addresses in SYN attacks
void handle_tcp(const unsigned char *network_payload, int verbose, uint32_t saddr) {
        struct tcphdr *tcp_header = (struct tcphdr *) network_payload;
        if(verbose) print_tcp_header(tcp_header);
        if(!(tcp_header->ack) && (tcp_header->syn)) {
                syn_packet_count++;
                check_unique_ip(saddr); //Will increment syn_unique_ip_count if unique
        }
        //Port 80 is the defined port number for HTTP requests
        if(ntohs(tcp_header->dest) == 80) {
                const unsigned char *transport_payload = network_payload + (tcp_header->doff * 4); //Skip over octets
                handle_http(transport_payload, verbose);
        }
}

//Checks the first 150 bytes of the HTTP request to see if it contains a banned URL
void handle_http(const unsigned char *transport_payload, int verbose) {
        char *payload_start = (char *) malloc(151); //Plus an extra byte for a null terminator
        strncpy(payload_start, (const char *) transport_payload, 150);
        //TODO: Make the blocklist an array of forbidden hosts, then check against each entry
        if(strstr((const char *) payload_start, "www.google.co.uk")) {
                if(verbose) printf("\nOutbound request to www.google.co.uk");
                blocklist_violation_count++;
        }
        free(payload_start);
}

//Checks an IP address against an array to see if it is a unique entry.
//If it is, then the address is added to the array.
void check_unique_ip(int ip_address) {
        int i;
        int flag = 0;
        for(i = 0; i < syn_unique_ip_count; i++) {
                if(ip_address == ip_array_ptr[i]) {
                        flag = 1;
                        break;
                }
        }

        if(!flag) {
                if(syn_unique_ip_count == ip_array_size) { //If we need to resize the array...
                        if(ip_array_size == 0) ip_array_size = 1; //Sanity check
                        int *tmp_ip_array_ptr = (int *) realloc(ip_array_ptr, (ip_array_size * 2) * sizeof(int));
                        ip_array_ptr = tmp_ip_array_ptr;
                        if(ip_array_ptr == NULL) { //Sanity check
                                printf("\nError: Could not realloc memory.");
                                exit(1);
                        }
                        ip_array_size = (ip_array_size * 2);
                }
                ip_array_ptr[syn_unique_ip_count] = ip_address;
                syn_unique_ip_count++;
        }
}

//Functions defined after this line print out the data in a human-readable form
void print_http_request(const char *http_request) {
        int bytes = strlen(http_request);
        int i;
        printf("\n");
        for(i = 0; i < bytes; ++i) {
                char byte = http_request[i];
                if(byte > 31 && byte < 127) {
                        printf("%c", byte);
                } else {
                        printf(".");
                }
        }

void print_tcp_header(struct tcphdr *tcp_header) {
        if((tcp_header->ack) && (tcp_header->syn)) {
                printf("\nSYN/ACK packet ");
        } else if((tcp_header->ack) && !(tcp_header->syn)) {
                printf("\nACK packet ");
        } else if(!(tcp_header->ack) && (tcp_header->syn)) {
                printf("\nSYN packet ");
        } else {
                printf("\nOther TCP packet type "); //As a default, fallback case
        }
        printf("on port %d", ntohs(tcp_header->dest));
}

void print_arp_packet(struct ether_arp *ether_arp_packet) {
        struct arphdr *arp_header = &ether_arp_packet->ea_hdr;

        if(ntohs(arp_header->ar_op) == 2) printf("\nARP Response from: ");
        else if(ntohs(arp_header->ar_op) == 1) printf("\nARP Request from: ");
        else (printf("%d", ntohs(arp_header->ar_op)));

        int i;
        for(i = 0; i < 4; i++) {
                printf("%d", ether_arp_packet->arp_spa[i]);
                if(i < 3) printf(".");
        }
}

void print_ip_header(struct iphdr *ip_header) {
        struct in_addr source;
        struct in_addr destination;

        source.s_addr = ip_header->saddr;
        destination.s_addr = ip_header->daddr;

        printf("\nSource IP: %s", inet_ntoa(source));
        printf("\nDest IP: %s", inet_ntoa(destination));

        printf("\nTransport Layer Protocol: ");
        switch(ip_header->protocol) {
                case 1:
                        printf("ICMP");
                        break;
                case 6:
                        printf("TCP");
                        break;
                case 17:
                        printf("UDP");
                        break;
                default:
                        printf("Unknown");
        }
