#ifndef V6SCAN_COMMON_H
#define V6SCAN_COMMON_H

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>

#include <pcap.h>

#include <v6scan/sys.h>

#define MAX(a, b) ((a>b) ? a : b)
#define MIN(a, b) ((a<b) ? a : b)

enum Debug {None=0, Fatal=1, Warning=2, Info=3};


#define NNMAP      8
#define DEHCPLIMIT 10000

#define OPT_METH  0x000000ff
#define OPT_PING  0x00000001
#define OPT_MAL   0x00000002
#define OPT_SNIFF 0x00000004
#define OPT_DELIM 0x00000008
#define OPT_NMAP  0x00000010
#define OPT_TARG4 0x00800000
#define OPT_TARG  0x01000000
#define OPT_MASK  0x02000000
#define OPT_IPV4  0x04000000
#define OPT_IPV6  0x08000000
#define OPT_FORCE 0x10000000
#define OPT_DUMP  0x20000000
#define OPT_DBG   0x40000000
#define OPT_QUIET 0x80000000

extern uint32_t OPTIONS;
extern uint32_t WAIT_TO_SEC;
extern uint32_t WAIT_TO_NSEC;
extern uint32_t ICMP_DELAY;
extern uint32_t MAX_ICMP;
extern uint32_t WINDOW;
extern uint8_t  EXIT_CODE;
extern uint8_t  THREAD_EXIT;
extern uint8_t  VERBOSE;

extern pcap_t *handle;

extern pthread_mutex_t filelock;
extern pthread_mutex_t stdoutlock;
extern pthread_mutex_t sqlqueuelock;
extern pthread_mutex_t pktprocqueuelock;

extern char dev[256];
extern char directory[256];


void makefilepath(char *, const char *, const char *, int, int);
#endif
