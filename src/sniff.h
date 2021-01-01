#include <pcap.h>
#include <pthread.h>
#ifndef IDS_SNIFF_H
#define IDS_SNIFF_H

void sniff(char *interface, int verbose);
void sig_handler(int signo);

#endif