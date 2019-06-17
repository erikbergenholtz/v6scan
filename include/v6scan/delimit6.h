#ifndef V6SCAN_DELIMIT6_H
#define V6SCAN_DELIMIT6_H

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <v6scan/icmp.h>

#define LOWER 0
#define UPPER 1

#define RECVTIMEOUT 1

#define BUFSIZE 0xffff

#define DELIM_SEND 0
#define DELIM_RECV 1

typedef __uint128_t uint128_t;

extern char seedaddr6[INET6_ADDRSTRLEN];
extern uint8_t seedmask6;

int  ping6(uint128_t, uint32_t);
void sweep6(uint128_t, uint128_t, int (*poke)(uint128_t, uint32_t));
void *rundelim6icmp(void *);
void *rundelim6nmap(void *);
void initdelimsock6(int *);
void ip6toint128(const struct sockaddr_in6, uint128_t *);
void int128toip6(const uint128_t src, struct sockaddr_in6 *addr);
uint128_t delimit6(uint128_t, uint128_t, char, int (*poke)(uint128_t, uint32_t), int *);

#endif
