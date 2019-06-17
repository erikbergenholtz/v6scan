#include <v6scan/host.h>

uint32_t filenum = 0;
const char *method_names[11] = {"ICMP", "Hop-by-Hop", "Eavesdrop", "DeHCPv6", "DeHCPv6 nmap", "DeHCPv4", "DeHCPv4 nmap"};
long nWrites = 0;
struct Host pktproc_host_queue[PKTPROC_QUEUE_LEN];
size_t pktproc_head = 0;
size_t pktproc_tail = 0;

void hostqueue_insert(const Host h){
   sem_wait(&pktproc_q_empty);
   pthread_mutex_lock(&pktprocqueuelock);
   pktproc_host_queue[pktproc_head] = h;
   pktproc_head = (pktproc_head + 1) % PKTPROC_QUEUE_LEN;
   pthread_mutex_unlock(&pktprocqueuelock);
   sem_post(&pktproc_q_full);
}

void *runhostprocessor(void *args)
{
   struct timespec timeout;
   char filepath[256];
   FILE *f;
   timeout.tv_sec = WAIT_TO_SEC;
   timeout.tv_nsec = WAIT_TO_NSEC;
   makefilepath(filepath, "dump", "csv", 256, filenum);
   debug("Dump directory: %s\n", directory);
   debug("Dump file name: `%s`\n", filepath);
   if(mkdir(directory, DIRMODE) == -1)
      if(errno != EEXIST)
         fatal("While creating directory `%s`: %s\n", directory, strerror(errno));
   if((f = fopen(filepath,"a")) == NULL)
      fatal("While opening file: %s\n", strerror(errno));
   while(1)
   {
      int ret = sem_timedwait(&pktproc_q_full, &timeout);
      if(ret == -1 && errno == ETIMEDOUT){
         if(THREAD_EXIT) break;
         else continue;
      }
      pthread_mutex_lock(&pktprocqueuelock);
      writehosttofile(f,&pktproc_host_queue[pktproc_tail]);
      pktproc_tail = (pktproc_tail + 1) % PKTPROC_QUEUE_LEN;
      pthread_mutex_unlock(&pktprocqueuelock);
      sem_post(&pktproc_q_empty);
   }
   if(fclose(f) == EOF)
      fatal("When closing file: %s\n", strerror(errno));
   debug("Exiting pktproc thread\n");
   return NULL;
}

void printhost(const Host *h, char *str)
{
   char mac[18];
   char ip[INET6_ADDRSTRLEN];
   char tstr[40];
   struct tm *t = localtime(&(h->host_time));
   strftime(tstr, sizeof(tstr), "%F %T %z", t);
   mac2str(h->host_mac, mac);
   ip2str(h, ip);
   sprintf(str, "IP: %s\nMac: %s\nRTT (ms): %lf\nTime: %s\nMethod: %s\n\n",
            ip, mac, h->host_rtt, tstr, method_names[h->host_method]);
}

void gethostip(const Host *h, char *str)
{
   ip2str(h, str);
}

void writehosttofile(FILE *f, const Host *h)
{
   debug("Writing host to file\n");
   char ipaddr[INET6_ADDRSTRLEN];
   char macaddr[18];
   char tstr[40];
   struct tm *t = localtime(&(h->host_time));
   ip2str(h, ipaddr);
   mac2str(h->host_mac, macaddr);
   strftime(tstr, sizeof(tstr), "%F %T %z", t);
   if(fprintf(f, "%s,%s,%s,%lf,%s\n", tstr, ipaddr, macaddr, h->host_rtt,
                                    method_names[h->host_method]) < 0)
      fatal("Could not write to file\n");
   debug("Written so far: %lu\n",++nWrites);
}

Host buildhost(void *ip, int family, struct ethhdr *eth, time_t time, double rtt, uint8_t method)
{
   Host h;
   h.family = family;
   if(h.family == AF_INET6){
      memcpy(&h.host_ip, (struct in6_addr *)ip, sizeof(struct in6_addr));
   } else {
      memcpy(&h.host_ipv4, (struct in_addr *)ip, sizeof(struct in_addr));
   }
   int i;
   for(i=0 ; i<6 ; ++i){
      if(eth) h.host_mac[i] = eth->h_source[i];
      else    h.host_mac[i] = 0;
   }
   h.host_time = time;
   h.host_rtt = rtt;
   h.host_method = method;
   return h;
}

void mac2str(const unsigned char *mac, char *buf){
   sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x", 
      (mac[0] & 0xff), (mac[1] & 0xff), (mac[2] & 0xff),
      (mac[3] & 0xff), (mac[4] & 0xff), (mac[5] & 0xff));
}

void str2mac(const char *buf, unsigned char *mac){
   unsigned int tmp[6];
   sscanf(buf, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2],
                                    &tmp[3], &tmp[4], &tmp[5]);
   int i=0;
   for(; i<6; ++i){
      mac[i] = (unsigned char)tmp[i];
   }
}

void ip2str(const Host *h, char *buf)
{
   if(h->family == AF_INET6)
      inet_ntop(AF_INET6, (char *)&h->host_ip, buf, INET6_ADDRSTRLEN);
   else
      inet_ntop(AF_INET, (char *)&h->host_ipv4, buf, INET_ADDRSTRLEN);
}
