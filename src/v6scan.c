#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <pthread.h>
#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <v6scan/sys.h>
#include <v6scan/sniff.h>
#include <v6scan/icmp.h>
#include <v6scan/delimit4.h>
#include <v6scan/delimit6.h>

char seedaddrtmp[INET6_ADDRSTRLEN];
char seedaddr4tmp[INET_ADDRSTRLEN];
char seedmasktmp[INET_ADDRSTRLEN] = "255.255.255.0";
int seedmask6tmp = 64;

void printhelp(char *argv[])
{
   printf("Usage: %s [OPTIONS]\n\n",argv[0]);
   printf("OPTIONS:\n");
   printf("-h           - Display help text\n");
   printf("-p           - Enable multicast ICMP scan\n");
   printf("-m           - Enable malformed multicast ICMP scan\n");
   printf("-s           - Enable eavesdropping\n");
   printf("-x           - Enable DHCP delimiting with ICMP\n");
   printf("-z           - Enable DHCP delimiting with `nmap`\n");
   printf("-4           - Run DeCHP in IPv4\n");
   printf("-6           - Run DeCHP in IPv6\n");
   printf("-I <iface>   - Choose interface (chosen by program unless specified)\n");
   printf("-a <addr>    - Send packets from <addr> (chosen by kernel unless specified)\n");
   printf("-T <addr>    - Use <addr> as seed address for delimiting IPv4 method\n");
   printf("-t <addr>    - Use <addr> as seed address for delimiting IPv6 method\n");
   printf("-P <length>  - Prefix length of for delimiting IPv6 method, default is 64\n");
   printf("-M <mask>    - Netmask of seed address, default it 255.255.255.0\n");
   printf("-o <dir>     - Choose output directory (default is `dump`)\n");
   printf("-N <num>     - Terminate program after <num> packets of each type are sent\n");
   printf("               If left out or set to 0 no limit is imposed.\n");
   printf("-w <num>     - Window size used by the DeHCP methods, default is 4\n");
   printf("-S           - Dump IPs to STDOUT as they are discovered\n");
   printf("-D <sec>     - ICMP delay in seconds (default is 1)\n");
   printf("-v           - Increase verbosity (up to three times)\n");
   printf("-q           - Quiet mode\n");
   printf("-d           - Enable debug messages\n");
}

void handleargs(int argc, char *argv[])
{
   opterr = 0; /* Tell getopt() to not write to stderr */
   char c;
   /*
    * -h         - Display help text
    * -p         - Enable multicast ICMP scan
    * -m         - Enable malformed multicast ICMP scan
    * -s         - Enable eavesdropping
    * -x         - Enable DHCP delimiting with ICMP
    * -z         - Enable DHCP delimiting with `nmap`
    * -4         - Run DeCHP in IPv4
    * -6         - Run DeCHP in IPv6
    * -I <iface> - Choose interface (chosen by program unless specified)
    * -a <addr>  - Send packets from <addr> (chosen by kernel unless specified)
    * -t <addr>  - Use <addr> as seed address for delimiting method
    * -M <mask>  - Netmask of seed address
    * -o <dir>   - Choose output directory (default is `dump`)
    * -N <num>   - Terminate program after <num> packets of each type are sent
    *              If left out or set to 0 no limit is imposed.
    * -w <num>   - Window size used by the DeHCP methods, default is 4
    * -S         - Dump IPs to STDOUT as they are discovered
    * -D <sec>   - ICMP delay in seconds (default is 1)
    * -v         - Increase verbosity (up to three times)
    * -q         - Quiet mode
    * -d         - Enable debug messages
    */
   while( (c = getopt(argc, argv, "hpmsxz46OI:a:T:t:P:M:o:N:w:SD:W:vdq")) != -1 )
   {
      char *tmp;
      switch(c)
      {
         case 'h':   // Print help text
            printhelp(argv);
            exit(0);
            break;
         case 'p':   // Enable multicast ping scan
            OPTIONS |= OPT_PING;
            break;
         case 'm':   // Enable "malformed" multicast ping scan
            OPTIONS |= OPT_MAL;
            break;
         case 's':   // Enable eavesdropping
            OPTIONS |= OPT_SNIFF;
            break;
         case 'x':   // Enable DeHCP with ICMP
            OPTIONS |= OPT_DELIM;
            break;
         case 'z':   // Enable DeHCP with `nmap`
            OPTIONS |= OPT_NMAP;
            break;
         case '4':   // Run DeHCP with IPv4
            OPTIONS |= OPT_IPV4;
            break;
         case '6':   // Run DeHCP with IPv6
            OPTIONS |= OPT_IPV6;
            break;
         case 'I':   // Chose interface
            strncpy(dev, optarg, 256);
            break;
         case 'a':   // Force chosen IP address when pinging
            OPTIONS |= OPT_FORCE;
            strncpy(source, optarg, INET6_ADDRSTRLEN);
            break;
         case 'T':   // Seed address for DeHCPv4 method
            OPTIONS |= OPT_TARG4;
            strncpy(seedaddr4tmp, optarg, INET_ADDRSTRLEN);
            break;
         case 't':   // Seed address for DeHCPv6 method
            OPTIONS |= OPT_TARG;
            strncpy(seedaddrtmp, optarg, INET6_ADDRSTRLEN);
            break;
         case 'P':   // Prefix length for DeHCPv6 method
            seedmask6tmp = strtol(optarg, &tmp, 10);
            if(*tmp != '\0' || !(0 <= seedmask6tmp && seedmask6tmp <= 128))
               fatal("Could not set prefix length `%s`\n", optarg);
            break;
         case 'M':   // Netmask of seed address
            OPTIONS |= OPT_MASK;
            strncpy(seedmasktmp, optarg, INET_ADDRSTRLEN);
            break;
         case 'o':   // Choose output directory
            strncpy(directory, optarg, 256);
            break;
         case 'N':   // Terminate after <num> packets of each type
            MAX_ICMP = strtol(optarg, &tmp, 10);
            if(*tmp != '\0')
               fatal("Could not set ICMP limit `%s`\n", optarg);
            break;
         case 'w':
            WINDOW = strtol(optarg, &tmp, 10);
            if(*tmp != '\0')
               fatal("Could not set Window size `%s`\n", optarg);
            break;
         case 'S':   // Dump IPs to STDOUT as they're found
            OPTIONS |= OPT_DUMP;
            break;
         case 'D':   // Set delay between ICMP messages
            ICMP_DELAY = strtol(optarg, &tmp, 10);
            if(*tmp != '\0')
               fatal("Could not set ICMP delay `%s`n", optarg);
            break;
         case 'v':   // Increase verbosity
            if(VERBOSE < 3) VERBOSE++;
            break;
         case 'q':   // Quiet mode
            OPTIONS |= OPT_QUIET;
            if(VERBOSE == 1) VERBOSE = 0;
            break;
         case 'd':   // Enable debug messages
            OPTIONS |= OPT_DBG;
            break;
         default:
            fatal("Unrecognized option: %c\n", c);
            break;
      }
   }
}

int main(int argc, char *argv[])
{
   pthread_t sniff_thread      = 0;
   pthread_t icmp_thread       = 0;
   pthread_t delim4icmp_thread = 0;
   pthread_t delim4nmap_thread = 0;
   pthread_t delim6icmp_thread = 0;
   pthread_t delim6nmap_thread = 0;
   pthread_t pktproc_thread    = 0;
   {
      debug("Handle CLI args\n");
      handleargs(argc, argv);
      signal(SIGINT, signalhandler);
      if((OPTIONS & OPT_METH) == 0)
         fatal("No methods chosen\n");
      if(OPTIONS & (OPT_DELIM | OPT_NMAP)){
         if(!(OPTIONS & (OPT_IPV6 | OPT_IPV4)))
            fatal("At least one of -4 and -6 must be specified for DeCHP methods\n");
         if((OPTIONS & OPT_IPV6) && !(OPTIONS & OPT_TARG))
            fatal("DeHCPv6 methods requires target\n");
         if((OPTIONS & OPT_IPV4) && !(OPTIONS & OPT_TARG4))
            fatal("DeHCPv4 methods requires target\n");
      }
   }

   {
      debug("Setting device\n");
      if(dev[0] == 0)
      {
         char errbuf[PCAP_ERRBUF_SIZE];
         strncpy(dev, pcap_lookupdev(errbuf), 256);
         if(dev == NULL)
            fatal("Could not find default device: %s\n", errbuf);
      }
      debug("Device set to `%s`\n", dev);
   }

   {
      debug("Setting output directory if not set\n");
      if(directory[0] == 0)
         strncpy(directory, "dump", 256);
      info("Using output directory %s\n",directory);
   }

   {
      debug("Initializing semaphores\n");
      if(sem_init(&pktproc_q_empty, 0, PKTPROC_QUEUE_LEN) != 0)
         fatal("While initializing `pktproc_q_empty`: %s\n", strerror(errno));
      if(sem_init(&pktproc_q_full, 0, 0) != 0)
         fatal("While initializing `pktproc_q_full`: %s\n", strerror(errno));
   }

   {
      debug("Starting threads\n");
      int err = 0;
      if((err = pthread_create(&pktproc_thread, NULL, runhostprocessor, NULL)) != 0)
         fatal("When starting PKTPROC thread: %s\n", strerror(err));
      if(OPTIONS & OPT_SNIFF)
      {
         debug("Initializing sniffing thread\n");
         if((err = pthread_create(&sniff_thread, NULL, runpcap, NULL)) != 0)
            fatal("When starting sniff thread: %s\n", strerror(err));
      }
      if(OPTIONS & (OPT_PING | OPT_MAL))
         if((err = pthread_create(&icmp_thread, NULL, runicmp, NULL)) != 0)
            fatal("When starting ICMP thread: %s\n", strerror(err));
      if((OPTIONS & OPT_DELIM) && (OPTIONS & OPT_IPV4)){
         strncpy(seedaddr4, seedaddr4tmp, INET_ADDRSTRLEN);
         strncpy(seedmask4, seedmasktmp, INET_ADDRSTRLEN);
         debug("DeHCPv4 icmp - Using address %s with mask %s\n", seedaddr4, seedmask4);
         if((err = pthread_create(&delim4icmp_thread, NULL, rundelim4icmp, NULL)) != 0)
            fatal("When starting DeHCPv4 icmp thread: %s\n", strerror(err));
      }
      if((OPTIONS & OPT_NMAP) && (OPTIONS & OPT_IPV4)){
         strncpy(seedaddr4, seedaddr4tmp, INET_ADDRSTRLEN);
         strncpy(seedmask4, seedmasktmp, INET_ADDRSTRLEN);
         debug("DeHCPv4 nmap - Using address %s with mask %s\n", seedaddr4, seedmask4);
         if((err = pthread_create(&delim4nmap_thread, NULL, rundelim4nmap, NULL)) != 0)
            fatal("When starting DeHCPv4 nmap thread: %s\n", strerror(err));
      }
      if((OPTIONS & OPT_DELIM) && (OPTIONS & OPT_IPV6)){
         strncpy(seedaddr6, seedaddrtmp, INET6_ADDRSTRLEN);
         seedmask6 = seedmask6tmp;
         debug("DeHCPv6 icmp - Using address %s/%d\n", seedaddr6, seedmask6);
         if((err = pthread_create(&delim6icmp_thread, NULL, rundelim6icmp, NULL)) != 0)
            fatal("When starting DeHCPv6 icmp thread: %s\n", strerror(err));
      }
      if((OPTIONS & OPT_NMAP) && (OPTIONS & OPT_IPV6)){
         strncpy(seedaddr6, seedaddrtmp, INET6_ADDRSTRLEN);
         seedmask6 = seedmask6tmp;
         debug("DeHCPv6 icmp - Using address %s/%d\n", seedaddr6, seedmask6);
         if((err = pthread_create(&delim6nmap_thread, NULL, rundelim6nmap, NULL)) != 0)
            fatal("When starting DeHCPv6 nmap thread: %s\n", strerror(err));
      }
   }

   {
      debug("Wait for threads\n");
      int ret = 0;
      if(sniff_thread && (ret = pthread_join(sniff_thread, NULL)) != 0)
         warning("When joining PCAP thread: %s\n", strerror(ret));
      if(icmp_thread && (ret = pthread_join(icmp_thread, NULL)) != 0)
         warning("When joining ICMP thread: %s\n", strerror(ret));
      if(delim4icmp_thread && (ret = pthread_join(delim4icmp_thread, NULL)) != 0)
         warning("When joining DeHCPv4 ICMP thread: %s\n", strerror(ret));
      if(delim4nmap_thread && (ret = pthread_join(delim4nmap_thread, NULL)) != 0)
         warning("When joining DeHCPv4 nmap thread: %s\n", strerror(ret));
      if(delim6icmp_thread && (ret = pthread_join(delim6icmp_thread, NULL)) != 0)
         warning("When joining DeCHPv6 ICMP thread: %s\n", strerror(ret));
      if(delim6nmap_thread && (ret = pthread_join(delim6nmap_thread, NULL)) != 0)
         warning("When joining DeHCPv6 nmap thread: %s\n", strerror(ret));
      THREAD_EXIT = 1;
      if(pktproc_thread && (ret = pthread_join(pktproc_thread, NULL)) != 0)
         warning("When joining PKTPROC thread: %s\n", strerror(ret));
   }
   exit(EXIT_CODE);
}
