#include "sniff.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <unistd.h>

//Opens network interface for packet capture then passes control to analysis function
void sniff(char *interface, int verbose) {
        setup_variables();

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 0, errbuf);

        if (pcap_handle == NULL) {
                fprintf(stderr, "Unable to open interface %s\n", errbuf);
                exit(EXIT_FAILURE);
        } else {
                printf("SUCCESS! Opened %s for capture\n", interface);
        }
        //Second argument of 0 to specify unlimited number of packets
        pcap_loop(pcap_handle, 0, analyse, (unsigned char *) verbose);
}

//If Control-C is pressed, stop capturing and print the metrics. Not signal safe.
void sig_handler(int signo) {
  if(signo == SIGINT) {
    print_report();
    exit(0);
  }
}