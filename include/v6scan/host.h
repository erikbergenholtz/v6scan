#ifndef V6SCAN_HOST_H
#define V6SCAN_HOST_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <dirent.h>
#include <semaphore.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>

#include <v6scan/common.h>
#include <v6scan/sys.h>

#define DIRMODE 0777
#define WRITESPERFILE 10000
#define PKTPROC_QUEUE_LEN 10000

extern uint32_t filenum;
extern const char *method_names[11];
extern long nWrites;

typedef struct Host
{
   struct in6_addr host_ip;
   struct in_addr host_ipv4;
   unsigned char host_mac[6];
   time_t host_time;
   double host_rtt;
   uint8_t host_method;
   uint32_t family;
}Host;


extern struct Host pktproc_host_queue[PKTPROC_QUEUE_LEN];
extern size_t pktproc_head;
extern size_t pktproc_tail;

sem_t pktproc_q_full;
sem_t pktproc_q_empty;

void hostqueue_insert(const Host);
void *runhostprocessor(void *);
void printhost(const Host *, char *);
void gethostip(const Host *, char *);
void writehosttofile(FILE *, const Host *);
Host buildhost(void *, int, struct ethhdr *, time_t, double, uint8_t);
void mac2str(const unsigned char*, char *);
void str2mac(const char*, unsigned char *);
void ip2str(const Host*, char *);

#endif // V6SCAN_HOST_H
