#ifndef V6SCAN_ICMP_H
#define V6SCAN_ICMP_H

#define _GNU_SOURCE // Make sure the inet6_opt_... functions are included

#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>

#include <v6scan/host.h>
#include <v6scan/common.h>
#include <v6scan/sys.h>
#include <v6scan/delimit6.h>

#define BUFSIZE 0xffff

#define WELLFORMED  0
#define MALFORMED   1
#define RECV_SOCKET 2

typedef __uint128_t uint128_t;

typedef struct {
   int  (*fproc) (char *, ssize_t, struct timeval*, struct sockaddr_in6*, uint16_t);
   int (*fsend) (int, struct sockaddr_in6, uint16_t, int);
   void (*finit[3]) (int *);
   struct sockaddr_in6 *sasend;   /* sockaddr{} for sending     */
   struct sockaddr_in6 *sarecv;   /* sockaddr{} for receiving   */
   int sa_family;                 /* socket family */
   socklen_t salen;               /* length of sockaddr{}s      */
   int icmpproto;                 /* IPPROTO_xxx value for ICMP */
} proto;

extern char   source[INET6_ADDRSTRLEN];
extern char   sendbuf[BUFSIZE];
extern int    datalen;
extern int    nsent;
extern pid_t  pid;
extern proto *pr;

int  proc(char *, ssize_t, struct timeval *, struct sockaddr_in6*, uint16_t);
int sendicmp(int, struct sockaddr_in6, uint16_t, int);
void *runicmp(void *);
void initsocket(int *);
void initsocket_mal(int *);
void initsocket_recv(int *);
void readloop(void);
void sig_alrm(int);
void tv_sub(struct timeval *, struct timeval *);
void getrttgen(void *, struct timeval *, double *, void (*extract)(void *, struct timeval **));

#endif
