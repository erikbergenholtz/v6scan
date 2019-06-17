#ifndef V6SCAN_DELIMIT_H
#define V6SCAN_DELIMIT_H

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <v6scan/icmp.h>

#define LOWER 0
#define UPPER 1

#define RECVTIMEOUT 1

#define INET_ADDSTRLEN 15
#define BUFSIZE 0xffff

#define DELIM_SEND 0
#define DELIM_RECV 1

extern char seedaddr4[INET_ADDRSTRLEN];
extern char seedmask4[INET_ADDRSTRLEN];

uint32_t delimit4(uint32_t, uint32_t, char, int (*poke)(uint32_t, uint32_t), int *);
void sweep4(uint32_t, uint32_t, int (*poke)(uint32_t, uint32_t));
void *rundelim4(void *);
void *rundelim4icmp(void *);
void *rundelim4nmap(void *);
void initdelimsock(int *);

#endif
