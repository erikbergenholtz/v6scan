#ifndef V6SCAN_SNIFF_H
#define V6SCAN_SNIFF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <v6scan/common.h>
#include <v6scan/sys.h>
#include <v6scan/host.h>

void *runpcap(void *);
int initpcap(pcap_t **);
void handlepacket(u_char *, const struct pcap_pkthdr *, const u_char *);
int savepacket(char *, const char*, size_t, size_t);

#endif
