#include <v6scan/sniff.h>

void *runpcap(void *v_args)
{
   //struct args_list *args = (struct args_list *)v_args;
   initpcap(&handle);//, args->argc, args->argv);
   debug("Handle value outside: %p\n", handle);
   debug("Handle pointer: %p\n", handle);
   pcap_loop(handle, -1, handlepacket, NULL);
   pcap_close(handle);
   debug("Exiting sniffing thread\n");
   return NULL;
}

int initpcap(pcap_t **handle)//, int argc, char **argv)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   char bpf_filter_str[] = "ip6"; // BPF cannot handle ICMPv6. Great.
   struct bpf_program bpf_filter;
   bpf_u_int32 netmask;
   bpf_u_int32 net;

   /*
    * Sounds in http://www.tcpdump.org/pcap.html like this function only applies
    * to IPv4
    */
   if(pcap_lookupnet(dev, &net, &netmask, errbuf) == -1)
   {
      warning("Cannot get netmask for device %s\n", dev);
      net = 0;
      netmask = 0;
   }
   info("Sniffing on device %s\n", dev);
   *handle = pcap_open_live(dev, BUFSIZ,1 , 1000, errbuf);
   debug("Handle value inside: %p\n", *handle);
   if(*handle == NULL)
      fatal("Could not open device %s: %s\n", dev, errbuf);

   if(pcap_datalink(*handle) != DLT_EN10MB)
      fatal("Device %s does not provide Ethernet headers - Not supported\n",dev);

   /*
    * Compile and set packet filter
    */
   if(pcap_compile(*handle, &bpf_filter, bpf_filter_str, 1, netmask) == -1)
      fatal("Failed to compiled BPF filter %s: %s\n", bpf_filter_str,pcap_geterr(*handle));
   if(pcap_setfilter(*handle, &bpf_filter) == -1)
      fatal("%s Failed to set BPF filter %s: %s\n",bpf_filter_str,pcap_geterr(*handle));
   return 0;
}

void handlepacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
   if(THREAD_EXIT){
      pcap_breakloop(handle);
      return;
   }
#define SIZE_ETHERNET 14
   struct ethhdr *ether;
   ether = (struct ethhdr *)(packet);
   debug("Ethernet type: %x\n", ether->h_proto);
   info("Sniffed a packet of length [%d]\n", header->len);
   if(ntohs(ether->h_proto) == 0x86dd)
   {
      struct ip6_hdr* ip;
      ip = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
      if(ip->ip6_nxt == 58) // is the next header ICMPv6?
      {
         struct icmp6_hdr *icmp = (struct icmp6_hdr *)(packet + SIZE_ETHERNET + 40);
         debug("ICMP type: %d\n", icmp->icmp6_type);
         if(icmp->icmp6_type == 128 || icmp->icmp6_type == 129 || icmp->icmp6_type == 4)
            return;
      }
      time_t t = time(NULL);
      Host src = buildhost((void *)&ip->ip6_src, AF_INET6, ether, t, 0, 2);
      hostqueue_insert(src);
      char str[256];
      if(VERBOSE == Info)
      {
         printhost(&src, str);
         info("%s", str);
      }
      if(OPTIONS & OPT_DUMP)
      {
         gethostip(&src, str);
         ok("%s\n", str);
      }
   }
   else
   {
      warning("Invalid Ethernet frame type: 0x%x\n", ntohs(ether->h_proto));
      return;
   }

}

int savepacket(char* packet, const char *fname, size_t off, size_t len){
   FILE *f = fopen(fname,"a");
   if(f == NULL)
   {
      fatal("Could not open file `%s` for writing\n", fname);
   }
   fwrite((char*)packet,1,len,f);
   fclose(f);
   return 0;
}
