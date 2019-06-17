#include <v6scan/delimit6.h>

#include <sys/wait.h>

int d_sockfds[2];
char seedaddr6[INET6_ADDRSTRLEN];
uint8_t seedmask6;
uint128_t IP6_LIMIT = -1;
uint128_t UPPER_LIMIT6 = 0;
uint128_t prefix6 = 0;
uint32_t nsent6icmp;
uint32_t nsent6nmap;
uint16_t delimid;

void initdelimrecvsock(int *);
int probe6(uint128_t, uint32_t);

void *rundelim6icmp(void *ingored)
{
   char fname[50];
   struct sockaddr_in6 seed = {0};
   uint128_t tmp;
   uint128_t t;
   uint128_t l;
   uint128_t u;
   struct sockaddr_in6 lower = {0};
   struct sockaddr_in6 upper = {0};
   FILE *delimprobes = NULL;
   {  // Initialize things
      debug("Starting delimit6icmp 128 bit thread\n");
      srand(time(0));
      delimid = getpid() ^ (rand() & 0xffff);
      initdelimsock6(&d_sockfds[DELIM_SEND]);
      initsocket_recv(&d_sockfds[DELIM_RECV]);
      debug("Seed address: %s\n", seedaddr6);
      inet_pton(AF_INET6, seedaddr6, (char *)&seed.sin6_addr);
      ip6toint128(seed, &tmp);
      nsent6icmp = 0;
      makefilepath(fname, "dehcp6-probes-icmp", "txt", 50, 0);
      debug("Writing v6 icmp probe info to: %s\n", fname);
      delimprobes = fopen(fname,"w");
   }

   {  // Determine netmask
      UPPER_LIMIT6 = 0;
      int i=0;
      for(; i<(128-seedmask6) ; ++i){
         UPPER_LIMIT6 = (UPPER_LIMIT6 << 1) + 1;
      }
      prefix6 = tmp & ~UPPER_LIMIT6;
      t = tmp & UPPER_LIMIT6;
   }

   {  // Find limits
      debug("Finding lower limit\n");
      int s = 0;
      l = delimit6(1, t, LOWER, ping6, &s);
      if(s == -2){
         debug("Exiting v6 thread\n");
         pthread_exit(NULL);
      }else if(s == -1){
         warning("Unable to find lower limit\n");
         return NULL;
      }
      debug("Lower limit is: %lu\n", l);
      debug("Finding upper limit\n");
      u = delimit6(t, UPPER_LIMIT6, UPPER, ping6, &s);
      if(s == -2){
         debug("Exiting v6 thread\n");
         pthread_exit(NULL);
      }else if(s == -1){
         warning("Unable to find upper limit\n");
         return NULL;
      }
      debug("Upper limit is: %lu\n", u);
   }

   {  // Rebuild IPv6 headers
      char sl[INET6_ADDRSTRLEN] = {0};
      char su[INET6_ADDRSTRLEN] = {0};
      tmp = prefix6 + l;
      int128toip6(tmp, &lower);
      inet_ntop(AF_INET6, (char *)&lower.sin6_addr, sl, INET6_ADDRSTRLEN);
      tmp = prefix6 + u;
      int128toip6(tmp, &upper);
      inet_ntop(AF_INET6, (char *)&upper.sin6_addr, su, INET6_ADDRSTRLEN);

      uint128_t _tmp = u-l;
      fprintf(delimprobes, "nmapv6 range: %s-%s, %016llx%016llx hosts\n", sl, su,
            ((long long unsigned int *)&_tmp)[1],
            ((long long unsigned int *)&_tmp)[0]);
      sweep6(l, u, ping6);

      close(d_sockfds[DELIM_SEND]);
      close(d_sockfds[DELIM_RECV]);
      fprintf(delimprobes, "ICMPv6 probes: %d\n", nsent6icmp);
      nsent6icmp = 0;
   }

   fclose(delimprobes);
   debug("Ending delimit thread\n");
   return NULL;
}

void *rundelim6nmap(void *ingored)
{
   char fname[50];
   struct sockaddr_in6 seed = {0};
   uint128_t tmp;
   uint128_t t;
   uint128_t l;
   uint128_t u;
   struct sockaddr_in6 lower = {0};
   struct sockaddr_in6 upper = {0};
   FILE *delimprobes = NULL;
   {  // Initialize things
      debug("Starting delimit6nmap 128bit thread\n");
      srand(time(0));
      delimid = getpid() ^ (rand() & 0xffff);
      initdelimsock6(&d_sockfds[DELIM_SEND]);
      initsocket_recv(&d_sockfds[DELIM_RECV]);
      debug("Seed address: %s\n", seedaddr6);
      inet_pton(AF_INET6, seedaddr6, (char *)&seed.sin6_addr);
      ip6toint128(seed, &tmp);
      nsent6nmap = 0;
      makefilepath(fname, "dehcp6-probes-nmap", "txt", 50, 0);
      debug("Writing v6 nmap probe info to: %s\n", fname);
      delimprobes = fopen(fname,"w");
   }

   {  // Determine netmask
      UPPER_LIMIT6 = 0;
      int i=0;
      for(; i<(128-seedmask6) ; ++i){
         UPPER_LIMIT6 = (UPPER_LIMIT6 << 1) + 1;
      }
      prefix6 = tmp & ~UPPER_LIMIT6;
      t = tmp & UPPER_LIMIT6;
      if(prefix6 + t == tmp) debug("It's working\n");
      struct sockaddr_in6 foo;
      char str[INET6_ADDRSTRLEN];
      int128toip6(tmp, &foo);
      inet_ntop(AF_INET6, (char *)&foo.sin6_addr, str, INET6_ADDRSTRLEN);
      debug("Target address: %s\n", str);
      int128toip6(t, &foo);
      inet_ntop(AF_INET6, (char *)&foo.sin6_addr, str, INET6_ADDRSTRLEN);
      debug("Host address: %s\n", str);
      int128toip6(prefix6, &foo);
      inet_ntop(AF_INET6, (char *)&foo.sin6_addr, str, INET6_ADDRSTRLEN);
      debug("Prefix address: %s\n", str);
      int128toip6(prefix6+t, &foo);
      inet_ntop(AF_INET6, (char *)&foo.sin6_addr, str, INET6_ADDRSTRLEN);
      debug("Glued address: %s\n", str);
   }

   {  // Find limits
      debug("Finding lower limit\n");
      int s = 0;
      l = delimit6(1, t, LOWER, probe6, &s);
      if(s == -2){
         debug("Exiting v6 thread\n");
         pthread_exit(NULL);
      }else if(s == -1){
         warning("Unable to find upper limit\n");
         return NULL;
      }
      debug("Lower limit is: %lu\n", l);
      debug("Finding upper limit\n");
      u = delimit6(t, UPPER_LIMIT6, UPPER, probe6, &s);
      if(s == -2){
         debug("Exiting v6 thread\n");
         pthread_exit(NULL);
      }else if(s == -1){
         warning("Unable to find upper limit\n");
         return NULL;
      }
      debug("Upper limit is: %lu\n", u);
   }

   {  // Rebuild IPv6 headers
      char sl[INET6_ADDRSTRLEN];
      char su[INET6_ADDRSTRLEN];
      tmp = prefix6 + l;
      int128toip6(tmp, &lower);
      inet_ntop(AF_INET6, (char *)&lower.sin6_addr, sl, INET6_ADDRSTRLEN);
      tmp = prefix6 + u;
      int128toip6(tmp, &upper);
      inet_ntop(AF_INET6, (char *)&upper.sin6_addr, su, INET6_ADDRSTRLEN);

      uint128_t _tmp = u-l;
      fprintf(delimprobes, "nmapv6 range: %s-%s, %016llx%016llx hosts\n", sl ,su,
         ((long long unsigned int *)&_tmp)[1],
         ((long long unsigned int *)&_tmp)[0]);
      sweep6(l, u, probe6);
      fprintf(delimprobes, "nmapv6 probes: %d\n", nsent6nmap);
      nsent6nmap = 0;
   }

   fclose(delimprobes);
   debug("Ending delimit thread\n");
   return NULL;
}


int awaitresponse6(struct sockaddr_in6 *target)
{
   char recvbuf[BUFSIZE];
   ssize_t n = 0;
   struct timeval s = {0};
   struct timeval e = {0};
   struct timeval tval = {0};
   struct timespec to = {0};
   to.tv_sec = 1;
   to.tv_nsec = 0;
   int retval = 0;
   fd_set rfd;
   {  // Initalize
      gettimeofday(&s, NULL);
      gettimeofday(&e, NULL);
   }

   tv_sub(&e, &s);
   while(e.tv_sec < 1){
      /*
       * No need for use of `pselect`, since `d_sockfds[DELIM_RECV]` is
       * initialized with a 1sec timeout
       */
      FD_ZERO(&rfd);
      FD_SET(d_sockfds[DELIM_RECV], &rfd);
      if((retval = pselect(d_sockfds[DELIM_RECV], &rfd, NULL, NULL, &to, NULL)) == -1){
         warning("pselect error: %s\n", strerror(errno));
         return 1;
      }else if(retval){
         if((n = recvfrom(d_sockfds[DELIM_RECV], recvbuf, BUFSIZE, 0, NULL, NULL)) < 0)
         {
            if(errno == EINTR) return 1;
            else{
               warning("`recvmsg()` error: %s\n", strerror(errno));
               return 1;
            }
         }
         gettimeofday(&tval, NULL);
         if(proc(recvbuf, n, &tval, target, delimid) == 0){
            debug("Got response!\n");
            return 0;
         }
      }
      gettimeofday(&e, NULL);
      tv_sub(&e, &s);
   }
   return 1;
}

int probe6(uint128_t addr, uint32_t n)
{
   debug("Issuing `nmap` probe\n");
   int ret                       = 1;
   struct timeval start[NNMAP]         = {{0}};
   struct timeval end[NNMAP]           = {{0}};
   struct sockaddr_in6 tmpaddr[NNMAP]  = {{0}};

   // Popen additions
   FILE *nmap[NNMAP]                   = {NULL};
   char macstr[NNMAP][20]              = {{0}};
   int isup[NNMAP]                     =  {0};

   int i;
   for(i=0 ; i<n ; ++i)
   {  // Build and run nmap
      uint128_t tmp;
      char cmd[256]                 = {0};
      char target[INET6_ADDRSTRLEN] = {0};
      tmp = prefix6 + addr + i;
      int128toip6(tmp, &tmpaddr[i]);
      inet_ntop(AF_INET6, &tmpaddr[i].sin6_addr, target, INET6_ADDRSTRLEN);
      debug("Probing %s\n", target);
      sprintf(cmd, "nmap -6 -n -sS -F -e %s %s", dev, target);
      gettimeofday(&start[i], NULL);
      if((nmap[i] = popen(cmd, "r")) == NULL)
         warning("While running command: %s\n", strerror(errno));
   }

   for(i=0 ; i<n ; ++i)
   {  // Process nmap
      if(nmap[i] == NULL) continue;
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
      if(pclose(nmap[i]) == -1)
         warning("Whlie closing command stream: %s\n", strerror(errno));
      gettimeofday(&end[i], NULL);
      nsent6nmap++;
   }

   for(i=0 ; i<n ; ++i)
   {
      if(isup[i]){  // Build Host
         ret = 0;
         tv_sub(&end[i], &start[i]);
         double rtt = end[i].tv_sec * 1000.0 + end[i].tv_usec / 1000.0;
         Host h;
         if(strlen(macstr[i]) > 0){
            struct ethhdr eth = {{0}};
            str2mac(macstr[i], eth.h_source);
            macstr[i][0] = 0;
            h = buildhost((void *)&tmpaddr[i].sin6_addr, AF_INET6, &eth, time(NULL), rtt, 4);
         }else
            h = buildhost((void *)&tmpaddr[i].sin6_addr, AF_INET6, NULL, time(NULL), rtt, 4);
         hostqueue_insert(h);
         if(VERBOSE == Info)
         {
            char str[256];
            printhost(&h, str);
            info("%s", str);
         }
         if(OPTIONS & OPT_DUMP)
         {
            char ip[INET6_ADDRSTRLEN];
            gethostip(&h, ip);
            ok("%s\n", ip);
         }
      }
   }
   return ret;
}

int ping6(uint128_t addr, uint32_t _){
   uint128_t tmp;
   struct sockaddr_in6 target = {0};
   tmp = prefix6 + addr;
   int128toip6(tmp, &target);
   if(sendicmp(d_sockfds[DELIM_SEND], target, delimid, ICMP6_ECHO_REQUEST) == -1)
      return 1;
   nsent6icmp++;
   return awaitresponse6(&target);
}

void sweep6(uint128_t l, uint128_t u, int (*poke)(uint128_t, uint32_t)){
   debug("Sweeping range %d - %d\n", MIN(l, u), MAX(l,u));
   uint128_t i = 0;
   i = MIN(l, u);
   u = MAX(l, u);
   uint32_t j = (poke == probe6) ? 8 : 1;
   for(i = l ; i <= u ; i+=j)
   {
      if(THREAD_EXIT) return;
      poke(i, MIN(u-i+1, j));
   }
}

void initdelimsock6(int *sockfd){
   uint32_t timeout = ICMP_DELAY*1000;
   initsocket(sockfd);
   if(setsockopt(*sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) > 0)
      fatal("Could not set timeout on socket\n");
}

uint128_t delimit6(uint128_t l, uint128_t r, char d, int (*poke)(uint128_t, uint32_t), int *s){
   if(THREAD_EXIT){
      *s = -2;
      return 0;
   }
   debug("Left: %lu Right: %lu\n", l, r);
   uint128_t m = (l/2)+(r/2);
   debug("Mid: %lu\n", m);
   if(l >= r) return l;
   if(l<0 || r>IP6_LIMIT){
      warning("l or r invalid\n");
      *s = -1;
      return 0;
   }
   if(poke(m,1) == 0)
   {
      if(d == LOWER) return delimit6(l, MAX(1, m-1), d, poke, s);
      else           return delimit6(MIN(IP6_LIMIT,m+1), r, d, poke, s);
   }else{
      uint128_t i   = MAX(m-WINDOW, l);
      uint128_t lim = MIN(m+WINDOW, r);
      for( ; i<=lim ; i++){
         if(THREAD_EXIT) return -2;
         if(poke(i, 1) == 0){
            if(d == LOWER) return delimit6(l, MAX(1, i-1), d, poke, s);
            else           return delimit6(MIN(IP6_LIMIT, i+1), r, d, poke, s);
         }
      }
      if(d == LOWER) return delimit6(MIN(IP6_LIMIT, m+1), r, d, poke, s);
      else           return delimit6(l, MAX(1, m-1), d, poke, s);
   }
}

void ip6toint128(const struct sockaddr_in6 addr, uint128_t *result){
   uint32_t *from = (uint32_t *)&addr.sin6_addr;
   *result = ntohl(from[0]);
   *result <<= 32;
   *result += ntohl(from[1]);
   *result <<= 32;
   *result += ntohl(from[2]);
   *result <<= 32;
   *result += ntohl(from[3]);
}

void int128toip6(const uint128_t src, struct sockaddr_in6 *addr){
   uint64_t *target = (uint64_t *)&addr->sin6_addr;
   uint32_t *from = (uint32_t *)&src;
   target[1] = (((uint64_t)(htonl(from[0]))) << 32)
             +   (uint64_t)(htonl(from[1]));
   target[0] = (((uint64_t)(htonl(from[2]))) << 32)
             +   (uint64_t)(htonl(from[3]));
}
