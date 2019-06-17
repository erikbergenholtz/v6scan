#include <v6scan/icmp.h>

int   sockfds[3];
char  source[INET6_ADDRSTRLEN];
int   icmp_cnt;
int   icmp_tot;
char  sendbuf[BUFSIZE];
int   datalen;
int   nsent;
pid_t pid;
proto *pr;
proto proto_v6 = {proc, sendicmp, {initsocket, initsocket_mal, initsocket_recv}, NULL, 0, IPPROTO_ICMPV6};

/* `main()` of the ICMP thread */
void *runicmp(void *args)
{
   debug("ICMP THREAD ID: %d\n", pthread_self());
   int has_printed = 0;
   sigset_t sigset;
   sigemptyset(&sigset);
   sigaddset(&sigset, SIGINT);
   pthread_sigmask(SIG_BLOCK, &sigset, NULL);
   pid = getpid() & 0xffff; /* ICMP PID field is just 16 bits */
   signal(SIGALRM, sig_alrm);
   { // Initialize protocol
      pr = &proto_v6;
      pr->sasend = NULL;
      pr->sarecv = NULL;
      if((pr->sasend = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6))) == NULL)
         fatal("Could not allocate memory for address\n");
      if((pr->sarecv = (struct sockaddr_in6 *)malloc(sizeof(struct sockaddr_in6))) == NULL)
         fatal("Could not allocate memory for address\n");
      pr->salen = sizeof(struct sockaddr_in6);
      inet_pton(AF_INET6, "ff02::1", (char *)&pr->sasend->sin6_addr);
      pr->sarecv->sin6_family = AF_INET6;
   }
   if(VERBOSE == Info && !has_printed)
   {
      char dstAddr[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, (char *)&pr->sasend->sin6_addr, dstAddr, INET6_ADDRSTRLEN);
      info("Pinging %s on device %s\n", dstAddr, dev);
   }
   if(IN6_IS_ADDR_V4MAPPED(&((pr->sasend->sin6_addr))))
      fatal("Cannot ping IPv4-mapped IPv6 address\n");
   readloop();
   { // Clean up
      if(pr->sasend) free(pr->sarecv);
      if(pr->sasend) free(pr->sasend);
      if(close(sockfds[WELLFORMED]) == -1)
         warning("While closing wellformed socket: %s\n", strerror(errno));
      if(close(sockfds[MALFORMED]) == -1)
         warning("While closing malformed socket: %s\n", strerror(errno));
      if(close(sockfds[RECV_SOCKET]) == -1)
         warning("While closing receive socket: %s\n", strerror(errno));
   }
   debug("Exiting ICMP `readloop()`\n");
   return NULL;
}

void initsocket(int *sockfd)
{
   struct icmp6_filter filter;
   int offset = 2;
   {  // Build socket
      if((*sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
         fatal("While creating socket: %s\n", strerror(errno));
      debug("Socket created with fd %d\n",*sockfd);
   }

   {  // Set mandatory socket options
      ICMP6_FILTER_SETBLOCKALL(&filter);
      ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
      if(setsockopt(*sockfd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) > 0)
         fatal("Could not set header IPV6_CHECKSUM\n");
      if(setsockopt(*sockfd, IPPROTO_IPV6, ICMP6_FILTER, &filter, sizeof(filter)) > 0)
         fatal("Could not set ICMPv6 filter\n");
      if(setsockopt(*sockfd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) > 0)
         fatal("Could not set device %d on socket\n", dev);
   }
   if(OPTIONS & OPT_FORCE){
      struct sockaddr_in6 addr;
      addr.sin6_family = AF_INET6;
      debug("Address to force: %s\n", source);
      inet_pton(AF_INET6, source, (char*)&addr.sin6_addr);
      if( bind(*sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1)
         fatal("Could not force global address: %s\n", strerror(errno));
   }
}

void initsocket_mal(int *sockfd)
{
   initsocket(sockfd);
   int on = 1;
   debug("Enabling Hop-by-Hop header\n");
   if(setsockopt(*sockfd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &on, sizeof(on)) > 0)
      fatal("Could not set Hop-by-Hop header on socket\n");
}

void initsocket_recv(int *sockfd){
   if((*sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6))) == -1)
      fatal("While creating socket: %s\n", strerror(errno));
}

void sethopheader(struct msghdr* msg, struct iovec *iov)
{
   struct cmsghdr *cmsg;
   void *hopbuf;
   socklen_t hoplen;
   void *databuf;
   int curlen;

   debug("Set hop-by-hop option\n");
   {
      debug("Find length of Hop-by-Hop header\n");
      if((curlen = inet6_opt_init(NULL, 0)) == -1)
         fatal("In `inet6_opt_init`: %s\n", strerror(errno));
      if((curlen = inet6_opt_append(NULL, 0, curlen, 0x80, 2, 1, NULL)) == -1)
         fatal("In `inet6_opt_appaned`: %s\n", strerror(errno));
      if((curlen = inet6_opt_finish(NULL, 0, curlen)) == -1)
         fatal("In `inet6_opt_finish`: %s\n", strerror(errno));
      hoplen = curlen;
   }

   {
      debug("Allocat memory for options header\n");
      cmsg = (struct cmsghdr*)malloc(CMSG_SPACE(hoplen));
      cmsg->cmsg_len = CMSG_LEN(hoplen);
      cmsg->cmsg_level = IPPROTO_IPV6;
      cmsg->cmsg_type = IPV6_HOPOPTS;
      hopbuf = CMSG_DATA(cmsg);
   }

   {
      debug("Construct Hop-by-Hop header\n");
      uint8_t val = 0x80;
      if((curlen = inet6_opt_init(hopbuf, hoplen)) == -1)
         fatal("In `inet6_opt_init`: %s\n", strerror(errno));
      *(unsigned char*)(hopbuf) = 59;
      if((curlen = inet6_opt_append(hopbuf, hoplen, curlen, 0x80, 2, 1, &databuf)) == -1)
         fatal("In `inet6_opt_append`: %s\n", strerror(errno));
      if(inet6_opt_set_val(databuf, 0, &val, sizeof(val)) == -1)
         fatal("In `inet6_opt_set_val`: %s\n", strerror(errno));
      if((curlen = inet6_opt_finish(hopbuf, hoplen, curlen)) == -1)
         fatal("In `inet6_opt_finish`: %s\n", strerror(errno));
   }

   {
      debug("Add options to message\n");
      iov[1].iov_base = hopbuf;
      iov[1].iov_len = sizeof(hopbuf);
      msg->msg_control = cmsg;
      msg->msg_controllen = CMSG_SPACE(hoplen);
   }
   return;
}

int sendicmp(int sockfd, struct sockaddr_in6 target, uint16_t icmpid, int type)
{
   if(THREAD_EXIT) return -1;
   int len;
   struct icmp6_hdr *icmp;
   struct msghdr msg = {0};
   struct iovec iov[2];
   char addr[INET6_ADDRSTRLEN];

   {
      debug("Build ICMP header\n");
      icmp = (struct icmp6_hdr *)sendbuf;
      icmp->icmp6_type = type;
      icmp->icmp6_code = 0;
      icmp->icmp6_id = icmpid;
      icmp->icmp6_seq = nsent++;

      memset((icmp+1), 0xa5, datalen);
      gettimeofday((struct timeval *)(icmp+1), NULL);
      debug("Timestamp: %x\n",(icmp+1));
      len = 8 + datalen + sizeof(struct timeval);
   }

   /*
    * Set IO buffer to be ICMP header object
    */

   {  // Build msghdr struct
      debug("Build `struct msghdr`\n");
      iov[0].iov_base = sendbuf;
      iov[0].iov_len = len;
      memset(&msg, 0, sizeof(msg));

      if((!(OPTIONS & OPT_PING) || icmp_cnt == 1) && icmpid == pid)
         sethopheader(&msg, iov);
      msg.msg_name = &target;
      msg.msg_namelen = sizeof(target);
      msg.msg_iov = iov;
      msg.msg_iovlen = 1;
      if((!(OPTIONS & OPT_PING) || icmp_cnt == 1) && icmpid == pid)
         msg.msg_iovlen = 2;
   }

   {  // Send ICMP message
      inet_ntop(AF_INET6, (char*)&target.sin6_addr, addr, INET6_ADDRSTRLEN);
      debug("Sending ICMP packet to %s\n",addr);
      debug("Socket: %d\n",sockfd);
      if(sendmsg(sockfd, &msg, 0) == -1){
         warning("While sending packet: %s\n",strerror(errno));
         return -1;
      }
      debug("ICMP echo request sent to %s\n",addr);
   }

   { // Clean up
   if((!(OPTIONS & OPT_PING) || icmp_cnt == 1) && !(OPTIONS & OPT_DELIM))
      free(msg.msg_control);
   }
   return 0;
}

void extractv6(void *pkt, struct timeval **tvsend)
{
   debug("Extracting time sent from ICMPv6\n");
   struct icmp6_hdr *icmp = (struct icmp6_hdr *)pkt;
   *tvsend = (struct timeval *)(icmp+1);
   debug("Time sent extracted\n");
}

void getrttgen(void *icmp, struct timeval *tvrecv, double *rtt, void (*extract) (void *, struct timeval **)){
   struct timeval *tvsend = NULL;
   if(extract)
      extract(icmp, &tvsend);
   tv_sub(tvrecv, tvsend);
   *rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
   debug("RTT decided\n");
}
void getrtt(struct icmp6_hdr *icmp, struct timeval *tvrecv, double *rtt){

   struct timeval *tvsend;
   tvsend = (struct timeval *)(icmp+1);
   tv_sub(tvrecv, tvsend);
   *rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;
   debug("RTT decided\n");
}

int proc(char *pkt, ssize_t len, struct timeval *tvrecv, struct sockaddr_in6 *t, uint16_t id){
   double rtt;
   struct ethhdr *eth;
   struct ip6_hdr *ip;
   struct icmp6_hdr *icmp;
   uint8_t method;

   eth = (struct ethhdr *)pkt;
#define ETHERNET_SIZE 14
   ip = (struct ip6_hdr *)(pkt + ETHERNET_SIZE);
   if(ip->ip6_nxt != 0x3a) return -1;
   icmp = (struct icmp6_hdr *)(pkt + ETHERNET_SIZE + 40);

   debug("Processing packet\n");

   if(len < 8)
      return 1;
   debug("Packet is long enough\n");

   if(t){
      char addr[INET6_ADDRSTRLEN] = {0};
      struct sockaddr_in6 r;
      memcpy(&r.sin6_addr, &ip->ip6_src, sizeof r.sin6_addr);
      uint128_t taddr;
      uint128_t raddr;
      ip6toint128(*t, &taddr);
      ip6toint128(r, &raddr);
      inet_ntop(AF_INET6, (char*)&t->sin6_addr, addr, INET6_ADDRSTRLEN);
      debug("Target address:   %s\n", addr);
      inet_ntop(AF_INET6, (char*)&ip->ip6_src, addr, INET6_ADDRSTRLEN);
      debug("Received address: %s\n", addr);
      if(taddr != raddr)
         return -1;
   }

   /*
    * If ICMP response was parameter problem message, extract the ICMP packet
    * that was returned. This is necessary to find the RTT
    */
   if(icmp->icmp6_type == ICMP6_PARAM_PROB) method = 1;
   else method = 0;
   debug("Method is: %d\n", method);
   if(icmp->icmp6_type == ICMP6_PARAM_PROB)
   {
      debug("Peeling off ICMPv6 from original packet");
      struct ip6_hdr *tmp_ip = (struct ip6_hdr *)(icmp+1);
      struct ip6_hbh *tmp_hbh = (struct ip6_hbh *)(tmp_ip+1);
      if(tmp_hbh->ip6h_nxt != 0x3a)
         return 1;
      icmp = (struct icmp6_hdr *)((char *)tmp_hbh + (tmp_hbh->ip6h_len+1)*8);
   }
   if(method != 1 && icmp->icmp6_id != pid) method = 3;
   debug("Sought ID: %u\n", id);
   debug("Found ID:  %u\n", icmp->icmp6_id);
   if(icmp->icmp6_id != id)
      return 1;
   debug("Found response to our msg\n");

   //getrtt(icmp, tvrecv, &rtt);
   getrttgen(icmp, tvrecv, &rtt, extractv6);
   debug("Adding address to set\n");
   Host h = buildhost((void *)&ip->ip6_src, AF_INET6, eth, time(NULL), rtt, method);
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
   debug("Address added, mutex unlocked\n");
   return 0;
}

// Stupid wrapper function for less spaghetti
void _callinit(int option, int sockid, char *name){
   int size = 60*1024;
   if(option && pr->finit[sockid])
   {
      debug("Init %s socket\n", name);
      (*pr->finit[sockid])(&sockfds[sockid]);
      if(setsockopt(sockfds[sockid], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) > 0)
         fatal("Could not set socket receive buffer size\n");
   }
}

void readloop(void){
   char recvbuf[BUFSIZE];
   ssize_t n = 0;
   struct timeval tval = {0};
   struct timespec timeout = {0};
   timeout.tv_sec  = WAIT_TO_SEC;
   timeout.tv_nsec = WAIT_TO_NSEC;
   int retval = 0;
   fd_set rfd;
   debug("Entered `readloop()`\n");

   setuid(getuid());
   _callinit((OPTIONS & OPT_PING), WELLFORMED, "wellformed");
   _callinit((OPTIONS & OPT_MAL), MALFORMED, "malformed");
   _callinit(1, RECV_SOCKET, "recv");

   sig_alrm(SIGALRM);

   while(1){
      if(THREAD_EXIT) break;
      FD_ZERO(&rfd);
      FD_SET(sockfds[RECV_SOCKET], &rfd);
      if((retval = pselect(sockfds[RECV_SOCKET]+1, &rfd, NULL, NULL, &timeout, NULL)) == -1)
         fatal("ICMP Select error: %s\n", strerror(errno));
      else if(retval){
         if((n = recvfrom(sockfds[RECV_SOCKET], recvbuf, BUFSIZE, 0, NULL, NULL)) < 0)
         {
            if(errno == EINTR) continue;
            else fatal("`recvmsg()` error: %s\n",strerror(errno));
         }
         gettimeofday(&tval, NULL);
         (*pr->fproc)(recvbuf, n, &tval, NULL, pid);
      }
   }
   return;
}

void sig_alrm(int signal){
   debug("Alarm triggered\n");
   if(MAX_ICMP && icmp_tot == MAX_ICMP){
      debug("ICMP limit reached, terminating process\n");
      THREAD_EXIT = 1;
      if(handle)
         pcap_breakloop(handle);
   }else{
      if((OPTIONS & OPT_PING) && icmp_cnt == 0){
         debug("Sending wellformed echo request\n");
         (*pr->fsend)(sockfds[WELLFORMED], *pr->sasend, (uint16_t)pid, ICMP6_ECHO_REQUEST);
      }else{
         debug("Sending malformed echo request\n");
         (*pr->fsend)(sockfds[MALFORMED], *pr->sasend, (uint16_t)pid, ICMP6_ECHO_REQUEST);
      }
      icmp_cnt = (icmp_cnt+1) % ((OPTIONS & OPT_MAL) ? 2 : 1);
      icmp_tot++;
      debug("Alarm set for 1sec\n");
      alarm(ICMP_DELAY);
   }
}

void tv_sub(struct timeval *fst, struct timeval *snd){
   if ((fst->tv_usec -= snd->tv_usec) < 0)
   {
      --fst->tv_sec;
      fst->tv_usec += 1000000;
   }
   fst->tv_sec -= snd->tv_sec;
}
