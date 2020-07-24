#include <v6scan/delimit4.h>


int d_sockfds4[2];
char seedaddr4[INET_ADDRSTRLEN];
char seedmask4[INET_ADDRSTRLEN];
uint32_t UPPER_LIMIT = 0;
uint64_t prefix = 0;
uint32_t nsent4icmp;
uint32_t nsent4nmap;
uint16_t delimid;


uint16_t in_cksum(const u_short *, int);
void initdelimrecvsock(int *);
int ping4(uint32_t, uint32_t);
int probe4(uint32_t, uint32_t);

void *rundelim4icmp(void *ingored)
{
   char fname[50];
   struct sockaddr_in seed = {0};
   uint32_t mask;
   uint32_t tmp;
   uint32_t l;
   uint32_t u;
   FILE *delimprobes = NULL;

   {  // Initialize things
      debug("Starting delimit4icmp thread\n");
      srand(time(0));
      delimid = getpid() ^ (rand() & 0xffff);
      initdelimsock(&d_sockfds4[DELIM_SEND]);
      initdelimrecvsock(&d_sockfds4[DELIM_RECV]);
      debug("Seed address: %s\n", seedaddr4);
      inet_pton(AF_INET, seedaddr4, (char *)&seed.sin_addr);
      tmp = ntohl(seed.sin_addr.s_addr);
      nsent4icmp = 0;
      makefilepath(fname, "dehcp4-probes-icmp","txt", 50, 0);
      debug("Writing v4 icmp probe info to %s\n", fname);
      delimprobes = fopen(fname,"w");
   }

   {  // Find upper limit
      inet_pton(AF_INET, seedmask4, (char *)&mask);
      mask = ntohl(mask);
      debug("Mask: 0x%08x\n", mask);
      UPPER_LIMIT = 0xffffffff ^ mask;
      debug("Upper limit    : 0x%08x\n", UPPER_LIMIT);
      debug("Upper limit inv: 0x%08x\n", ~UPPER_LIMIT);
      prefix = tmp & ~UPPER_LIMIT;
      tmp = tmp & UPPER_LIMIT;
   }

   {  // Find limits with ICMP
      debug("Finding lower limit\n");
      int s = 0;
      l = delimit4(1,tmp, LOWER, ping4, &s);
      if(s == -2){
         debug("Exiting DeHCPv4 thread\n");
         return NULL;
      }
      else if(s == -1){
         warning("Unable to find lower limit\n");
         return NULL;
      }
      debug("Lower limit is: %d\n", l);
      debug("Finding upper limit\n");
      u = delimit4(tmp, UPPER_LIMIT-1, UPPER, ping4, &s);
      if(s == -2){
         debug("Exiting DeHCPv4 thread\n");
         return NULL;
      }
      else if(s == -1){
         warning("Unable to find lower limit\n");
         return NULL;
      }
      debug("Upper limit is: %d\n", u);
      fprintf(delimprobes, "ICMPv4 range: %u - %u, %u\n",l, u, u-l);
      sweep4(l, u, ping4);
      close(d_sockfds4[DELIM_SEND]);
      close(d_sockfds4[DELIM_RECV]);
      fprintf(delimprobes, "ICMPv4 probes: %d\n", nsent4icmp);
      nsent4icmp = 0;
   }

   fclose(delimprobes);
   debug("Ending DeHCPv4 icmp thread\n");
   return NULL;
}

void *rundelim4nmap(void *ingored)
{
   char fname[50];
   struct sockaddr_in seed = {0};
   uint32_t mask;
   uint32_t tmp;
   uint32_t l;
   uint32_t u;
   FILE *delimprobes = NULL;

   {  // Initialize things
      debug("Starting delimit4 thread\n");
      srand(time(0));
      delimid = getpid() ^ (rand() & 0xffff);
      initdelimsock(&d_sockfds4[DELIM_SEND]);
      initdelimrecvsock(&d_sockfds4[DELIM_RECV]);
      debug("Seed address: %s\n", seedaddr4);
      inet_pton(AF_INET, seedaddr4, (char *)&seed.sin_addr);
      tmp = ntohl(seed.sin_addr.s_addr);
      nsent4nmap = 0;
      makefilepath(fname, "dehcp4-probes-nmap","txt", 50, 0);
      debug("Writing v4 nmap probe info to %s\n", fname);
      delimprobes = fopen(fname,"w");
   }

   {  // Find upper limit
      inet_pton(AF_INET, seedmask4, (char *)&mask);
      mask = ntohl(mask);
      debug("Mask: 0x%08x\n", mask);
      UPPER_LIMIT = 0xffffffff ^ mask;
      debug("Upper limit    : 0x%08x\n", UPPER_LIMIT);
      debug("Upper limit inv: 0x%08x\n", ~UPPER_LIMIT);
      prefix = tmp & ~UPPER_LIMIT;
      tmp = tmp & UPPER_LIMIT;
   }

   {  // Find limits with `nmap`
      debug("Finding lower limit\n");
      int s = 0;
      l = delimit4(1,tmp, LOWER, probe4, &s);
      if(s == -2){
         debug("Exiting DeHCPv4 nmap thread\n");
         return NULL;
      }
      else if(s == -1){
         warning("Unable to find lower limit\n");
         return NULL;
      }
      debug("Lower limit is: %d\n", l);
      debug("Finding upper limit\n");
      u = delimit4(tmp, UPPER_LIMIT-1, UPPER, probe4, &s);
      if(s == -2){
         debug("Exiting DeHCPv4 nmap thread\n");
         return NULL;
      }
      else if(s == -1){
         warning("Unable to find lower limit\n");
         return NULL;
      }
      debug("Upper limit is: %d\n", u);
      fprintf(delimprobes, "nmapv4 range: %d - %d, %d\n", l, u, u-l);
      sweep4(l, u, probe4);
      fprintf(delimprobes, "nmapv4 probes: %d\n", nsent4nmap);
      nsent4nmap = 0;
   }

   fclose(delimprobes);
   debug("Ending delimit thread\n");
   return NULL;
}

void __extract4(void *pkt, struct timeval **tvsend){
   struct icmp *icmp = (struct icmp*)pkt;
   *tvsend = (struct timeval *)icmp->icmp_data;
   debug("Cksum: 0x%04x\n", icmp->icmp_cksum);
   debug("tv_sec: %lu\n",  (*tvsend)->tv_sec);
   debug("tv_usec: %lu\n", (*tvsend)->tv_usec);
}

int proc4(char *pkt, ssize_t len, struct timeval *tv, struct sockaddr_in target)
{
   double         rtt   = 0;
   uint32_t       raddr = 0;
   uint32_t       taddr = 0;
   struct ethhdr *eth   = NULL;
   struct iphdr  *ip    = NULL;
   struct icmp   *icmp  = NULL;

   {  //Unpack received packet
#define ETHERNET_SIZE 14
      eth  = (struct ethhdr *)(pkt);
      ip   = (struct iphdr  *)(pkt + ETHERNET_SIZE);
      icmp = (struct icmp   *)(pkt + ETHERNET_SIZE + sizeof(struct iphdr));
   }

   {  // Check sender
      raddr = ntohl(ip->saddr);
      taddr = ntohl(target.sin_addr.s_addr);
      if(raddr != taddr)
         return 1;
   }
   if(icmp->icmp_type == ICMP_ECHOREPLY && icmp->icmp_id == delimid){
      debug("Got response from target\n");
      debug("Cksum: 0x%04x\n", icmp->icmp_cksum);
      getrttgen(icmp, tv, &rtt, __extract4);
      Host h = buildhost((void *)&ip->saddr, AF_INET, eth, time(NULL), rtt, 5);
      hostqueue_insert(h);
      if(VERBOSE == Info)
      {
         char str[256];
         printhost(&h, str);
         info("%s", str);
      }
      if(OPTIONS & OPT_DUMP)
      {
         char ip[INET_ADDRSTRLEN];
         gethostip(&h, ip);
         ok("%s\n", ip);
      }
      return 0;
   }
   return 1;
}


int awaitresponse(struct sockaddr_in target)
{
   char recvbuf[BUFSIZE];
   ssize_t n = 0;
   struct timeval s = {0};
   struct timeval e = {0};
   struct timeval tval = {0};

   {  // Initalize
      gettimeofday(&s, NULL);
      gettimeofday(&e, NULL);
   }

   tv_sub(&e, &s);
   while(e.tv_sec < 1){
      /*
       * No need for use of `pselect`, since `d_sockfds4[DELIM_RECV]` is
       * initialized with a 1sec timeout
       */
      if((n = recvfrom(d_sockfds4[DELIM_RECV], recvbuf, BUFSIZE, 0, NULL, NULL)) < 0)
      {
         if(errno == EINTR) return 1;
         else{
            warning("`recvmsg()` error: %s\n", strerror(errno));
            return 1;
         }
      }
      gettimeofday(&tval, NULL);
      if(proc4(recvbuf, n, &tval, target) == 0)
         return 0;
      gettimeofday(&e, NULL);
      tv_sub(&e, &s);
   }
   return 1;
}

int probe4(uint32_t addr, uint32_t n)
{
   debug("Issuing `nmap` probe\n");
   debug("Number of probes in parallel: %u\n", n);
   int ret                     = 1;
   struct sockaddr_in tmpaddr[NNMAP] = {{0}};
   struct timeval start[NNMAP]       = {{0}};
   struct timeval end[NNMAP]         = {{0}};

   // Popen additions
   FILE *nmap[NNMAP]                 = {NULL};
   char macstr[NNMAP][20]            = {{0}};
   int isup[NNMAP]                   = {0};

   int i;
   for(i=0 ; i<n ; ++i)
   {
      {  // Build command
         char cmd[291]                 = {0};
         char target[INET_ADDRSTRLEN]  = {0};
         *(uint32_t *)&tmpaddr[i].sin_addr = htonl(prefix + (addr+i));
         inet_ntop(AF_INET, &tmpaddr[i].sin_addr, target, INET_ADDRSTRLEN);
         debug("Probing %s\n", target);
         sprintf(cmd, "nmap -n -sS -F -e %s %s", dev, target);
         gettimeofday(&start[i], NULL);
         if((nmap[i] = popen(cmd, "r")) == NULL)
            warning("While running command: %s\n", strerror(errno));
      }
   }

   for(i=0 ; i<n ; ++i)
   {  // Run command
      if(nmap[i] == NULL) continue;
      debug("nmap file pointer: %p\n", nmap[i]);
      char buf[256] = {0};
      while(fgets(buf, sizeof(buf), nmap[i]) != 0){
         debug("%s", buf);
         char *needle;
         if((needle = strstr(buf, "open")) != NULL)
            isup[i] = 1;
         if((needle = strstr(buf, "MAC")) != NULL){
            char tmp[256] = {0};
            sscanf(needle, "%s %s %s", tmp, tmp, macstr[i]);
            isup[i] = 1;
         }
         buf[0] = 0;
      }
      debug("nmap file pointer: %p\n", nmap[i]);
      if(pclose(nmap[i]) == -1)
         warning("While closing command stream: %s\n", strerror(errno));
      gettimeofday(&end[i], NULL);
      nsent4nmap++;
   }

   for(i=0 ; i<n ; ++i)
   {
      debug("Building host %d\n", i);
      if(isup[i]){  // Build Host
         ret = 0;
         tv_sub(&end[i], &start[i]);
         double rtt = end[i].tv_sec * 1000.0 + end[i].tv_usec / 1000.0;
         debug("RTT determined\n");
         Host h;
         if(strlen(macstr[i]) > 0){
            debug("Mac found\n");
            struct ethhdr eth = {{0}};
            str2mac(macstr[i], eth.h_source);
            macstr[i][0] = 0;
            h = buildhost((void *)&tmpaddr[i].sin_addr, AF_INET, &eth, time(NULL), rtt, 6);
         }else{
            debug("No MAC address\n");
            h = buildhost((void *)&tmpaddr[i].sin_addr, AF_INET, NULL, time(NULL), rtt, 6);
         }
         debug("Host built\n");
         hostqueue_insert(h);
         if(VERBOSE == Info)
         {
            char str[256];
            printhost(&h, str);
            info("%s", str);
         }
         if(OPTIONS & OPT_DUMP)
         {
            char ip[INET_ADDRSTRLEN];
            gethostip(&h, ip);
            ok("%s\n", ip);
         }
      }
   }
   return ret;
}

int ping4(uint32_t addr, uint32_t _)
{
   unsigned char sendbufdelim[BUFSIZE];
   struct icmphdr *icmp;
   struct sockaddr_in target = {0};
   int len = 0;
   int datalen = 56;
   struct msghdr msg = {0};
   struct iovec iov = {0};

   {  // Set address
      memset((char *)&target, 0, sizeof(target));
      *(uint32_t *)&target.sin_addr = htonl(prefix + addr);
      target.sin_family = AF_INET;
   }

   {  // Build ICMPv4 packet
      debug("Building ICMP header\n");
      icmp = (struct icmphdr *)sendbufdelim;
      icmp->type = ICMP_ECHO;
      icmp->code = 0;
      icmp->checksum = 0;
      icmp->un.echo.sequence = htons(nsent4icmp);
      icmp->un.echo.id = delimid;
      memset(icmp+1, 0x00, datalen);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      memcpy(icmp+1, &tv, sizeof(struct timeval));
      debug("tv_sec: %lu\n", tv.tv_sec);
      debug("tv_usec: %lu\n", tv.tv_usec);
      len = 8 + datalen;
      icmp->checksum = in_cksum((u_short *)icmp, len);
   }

   {  //Build msghdr struct
      debug("Building `struct msghdr`\n");
      iov.iov_base = sendbufdelim;
      iov.iov_len = len;
      msg.msg_name = &target;
      msg.msg_namelen = 16;
      msg.msg_iov = &iov;
      msg.msg_iovlen = 1;
   }

   {  // Send ICMP message and await response
      char tmpaddr[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &target.sin_addr, tmpaddr, INET_ADDRSTRLEN);
      debug("Sending ICMP to %s\n", tmpaddr);
      debug("Socket fd: %d\n", d_sockfds4[DELIM_SEND]);
      if(sendmsg(d_sockfds4[DELIM_SEND], &msg, 0) == -1){
         warning("`sendmsg` error (ping4): %s\n", strerror(errno));
         return 1;
      }
      nsent4icmp++;
   }
   return awaitresponse(target);
}

void sweep4(uint32_t l, uint32_t u, int (*poke)(uint32_t, uint32_t)){
   debug("Sweeping range %d - %d\n", MIN(l, u), MAX(l,u));
   uint32_t i = 0;
   i = MIN(l, u);
   u = MAX(l, u);
   uint32_t j = (poke == probe4) ? 8 : 1;
   for(; i <= u ; i+=j)
   {
      if(THREAD_EXIT) return;
      poke(i, MIN(u-i+1,j));
   }
}

void initdelimrecvsock(int *sockfd){
   if((*sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
      fatal("While creating socket: %s\n", strerror(errno));
   debug("Delim recv socket created with fd %d\n", *sockfd);
}

void initdelimsock(int *sockfd){
   uint32_t timeout = ICMP_DELAY*1000;
   if((*sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
      fatal("While creating IPv4 socket: %s\n", strerror(errno));
   debug("Delim socket created with fd %d\n", *sockfd);
   if(setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) > 0)
      fatal("Could not set device %d on socket\n");
   if(setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) > 0)
      fatal("Could not set timeout on socket\n");
}

uint16_t in_cksum(const u_short *addr, int len)
{
   int nleft = len;
   uint32_t sum = 0;
   const u_short *w = addr;
   u_short answer = 0;
   while(nleft > 1)
   {
      sum += *w++;
      nleft -= 2;
   }
   if(nleft == 1)
   {
      sum += *(unsigned char *) w;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);
   answer = ~sum;
   return answer;
}

uint32_t delimit4(uint32_t l, uint32_t r, char d, int (*poke)(uint32_t, uint32_t), int *s){
   if(THREAD_EXIT){
      *s = -2;
      return 0;
   }
   debug("Left: %lu Right: %lu\n", l, r);
   uint32_t m = (uint32_t)((l/2.0)+(r/2.0));
   debug("Mid: %ld\n", m);
   if(l >= r) return m;
   if(l<1 || r>UPPER_LIMIT){
      *s = -1;
      return 0;
   }
   if(poke(m, 1) == 0)
   {
      if(d == LOWER) return delimit4(l, MAX(1, m-1), d, poke, s);
      else return delimit4(MIN(UPPER_LIMIT, m+1), r, d, poke, s);
   }
   else{
      uint32_t i   = MAX(m-WINDOW, l);
      uint32_t lim = MIN(m+WINDOW, r);
      for( ; i<=lim ; i++){
         if(THREAD_EXIT) return -2;
         if(poke(i, 1) == 0){
            if(d == LOWER) return delimit4(l, MAX(1, i-1), d, poke, s);
            else return delimit4(MIN(UPPER_LIMIT, i+1), r, d, poke, s);
         }
      }
      if(d == LOWER) return delimit4(MIN(UPPER_LIMIT, m+1), r, d, poke, s);
      else return delimit4(l, MAX(1, m-1), d, poke, s);
   }
}
