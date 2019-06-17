#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX(x,y)  ((x>=y) ? x : y)
#define MIN(x,y)  ((x<=y) ? x : y)

/*
 * Binary search inspired method for finding the DHCP pool
 *
 * 1. Decide on an IP address to start from
 * 2. Find the IP address half-way between the starting point and the network
 *    max address
 * 3. Ping the address. If there is an answer, go halfway up again until there
 *    is no answer
 * 4. If there is no answer, ping the closest 10 addresses (cur+-5)
 * 5. If none answer, go halfway back to the last point that responded
 * 6. Repeat until h==l
 * 7. Repeat for upper and lower bound
 *
 * Complexity for this algorithm should be approximately Th(log2(n))
 */

#define LOWER    0
#define UPPER    1
#define N        1000000   // Network size
#define DSTART   450000    // Start of DHCP pool
#define DEND     550000    // End of DHCP pool
#define PREC     100000    // 0.001% precision for density
#define T        100       // Number of tests

char FILENAME[10];
uint8_t network[N]   = {0};
uint64_t totaldhcp   =  0;
uint64_t founddhcp   =  0;
uint64_t total       =  0;
uint64_t found       =  0;
uint64_t nping       =  0;
uint64_t prefix      =  0;


void runtest(uint32_t, uint32_t, uint32_t, uint64_t, FILE *);
void sweep(uint64_t, uint64_t);
int ping(uint64_t);
uint64_t binarySearch(uint64_t, uint64_t, int, uint8_t);
void ip6toint128(struct sockaddr_in6, uint64_t *);
void int128toip6(uint64_t *, struct sockaddr_in6 *);
void writetofile(FILE *, uint32_t, uint32_t, uint32_t, uint64_t, int, int, double);
void tv_sub(struct timeval *, struct timeval *);
void makeheader(FILE *);


int main(int argc, char **argv){
   if(argc < 2){
      printf("Usage: %s WINDOW\n", argv[0]);
      exit(1);
   }
   srand(time(NULL));
   uint32_t w = atoi(argv[1]);
   sprintf(FILENAME, "%u.csv", w);
   uint64_t start = (DSTART+DEND)/2;
   uint64_t starts[] = { (DSTART/2),
                         (((DSTART+DEND)/2)-((DEND-DSTART)/4)),
                         (DSTART+DEND)/2,
                         (((DSTART+DEND)/2)+((DEND-DSTART)/4)),
                         ((N-DEND)/2)+DEND
                       };

   FILE *f = fopen(FILENAME, "a");
   makeheader(f);

   for(int i=0 ; i<=0 ; ){             // General network density
      for(int j=i ; j<=PREC ; ){          // DHCP network density
         for(int s=0 ; s < 5 ; ++s){        // Start seed
            for(int l=0 ; l<T ; ++l){     // Number of tests
               runtest(i, j, w, starts[s], f);
               fflush(f);
            }
         }
         if(j > 1000)     j += 5000;
         else if(j > 100) j += 4000;
         else             j *= 10;
      }
      if(i > 1000)     i += 5000;
      else if(i > 100) i += 4000;
      else             i *= 10;
   }
   fclose(f);
}

void makeheader(FILE *f){
   fprintf(f,"%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
      "oDens", "iDens", "win", "seed", "dLow", "dHigh", "nPing", "nFound", "total", "nFoundDhcp", "totalDhcp", "time");
}

void writetofile(FILE *f,        // File
                 uint32_t n,     // Network density
                 uint32_t d,     // DHCP density
                 uint32_t w,     // Window size
                 uint64_t s,     // Seed
                 int dl,         // Delta lower bound
                 int du,         // Delta upper bound
                 double tdiff    // Scan time
                ){
   fprintf(f,"%u,%u,%u,%lu,%d,%d,%lu,%lu,%lu,%lu,%lu,%lf\n", n, d, w, s, dl, du, nping, found, total, founddhcp, totaldhcp, tdiff);
}

void setup(uint32_t net, uint32_t dhcp){
   printf("Outer density: %lf%%\n", ((float)net/PREC)*100);
   printf("Inner density: %lf%%\n", ((float)dhcp/PREC)*100);
   total = 0;
   for(int i=0 ; i<N; ++i){
      if(rand()%PREC < net){
         network[i] = 1;
         ++total;
      } else network[i] = 0;
   }
   for(int i=DSTART ; i<=DEND ; ++i){
      if(rand()%PREC < dhcp){
         network[i] = 1;
         ++total;
         ++totaldhcp;
      } else network[i] = 0;
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

void runtest(uint32_t net, uint32_t dhcp, uint32_t w, uint64_t start, FILE *f){
   int l;
   char buf[INET6_ADDRSTRLEN];
   char buf2[INET6_ADDRSTRLEN];
   struct timeval tvstart    = {0};
   struct timeval tvend      = {0};
   struct sockaddr_in6 addr  = {0};
   struct sockaddr_in6 lower = {0};
   struct sockaddr_in6 upper = {0};
   uint64_t intaddr[2]       = {0};
   uint64_t low              =  0;
   uint64_t high             =  0;
   double timediff           =  0;

   printf("Net density: %f%%\n", ((float)net/PREC)*100);
   printf("DHCP density: %f%%\n", ((float)dhcp/PREC)*100);

   nping = 0;
   found = 0;
   setup(net, dhcp);
   gettimeofday(&tvstart, NULL);
   low = binarySearch(0, start, LOWER, w);
   high = binarySearch(start, N-1, UPPER, w);
   sweep(low, high);
   gettimeofday(&tvend, NULL);
   tv_sub(&tvend, &tvstart);
   timediff = tvend.tv_sec * 1.0 + tvend.tv_usec / 1000000.0;

   writetofile(f, net, dhcp, w, start, low-DSTART, high-DEND, timediff);

}

void sweep(uint64_t l, uint64_t h){
   for(uint64_t i=l ; i<=h ; ++i){
      if(network[i] == 1) ++found;
   }
}

int ping(uint64_t target){
   struct sockaddr_in6 tmp;
   char buf[INET6_ADDRSTRLEN] = {0};
   uint64_t tmp2[2] = {0};
   tmp2[0] = prefix;
   tmp2[1] = target;
   int128toip6(tmp2, &tmp);
   inet_ntop(AF_INET6, (char *)&tmp.sin6_addr, buf, INET6_ADDRSTRLEN);
   ++nping;
   if(network[target] >= 1){
      if(network[target] == 1){
         if(DSTART <= target && target <= DEND)
            ++founddhcp;
         ++found;
      }
      network[target] = 2;
      return 1;
   }
   return 0;
}


uint64_t binarySearch(uint64_t l, uint64_t r, int d, uint8_t w){
   uint64_t m = (l+r)/2;
   printf("l: %lu r: %lu m: %lu\n", l, r, m);
   if(l >= r) return m;
   if(l<0 || r>=N) return -1;
   if(ping(m)) {
      if(d == LOWER) return binarySearch(l, MAX(0, m-1), d, w);
      else           return binarySearch(MIN(N-1,m+1), r, d, w);
   } else {
      uint64_t i   = MAX(m-w, l);
      uint64_t lim = MIN(m+w, r);
      for( ; i<=lim ; i++){
         if(ping(i)){
            if(d == LOWER) return binarySearch(l, MAX(0,i-1), d, w);
            else           return binarySearch(MIN(N-1,i+1), r, d, w);
         }
      }
      if(d == LOWER) return binarySearch(MIN(N-1,m+1), r, d, w);
      else           return binarySearch(l, MAX(0,m-1), d, w);
   }
}

void ip6toint128(struct sockaddr_in6 addr, uint64_t *result){
   uint32_t *from = (uint32_t *)&addr.sin6_addr;
   result[0] = ((uint64_t)ntohl(from[0]) << 32)
             +  (uint64_t)ntohl(from[1]);
   result[1] = ((uint64_t)ntohl(from[2]) << 32)
             +  (uint64_t)ntohl(from[3]);
}

void int128toip6(uint64_t *src, struct sockaddr_in6 *addr){
   uint64_t *target = (uint64_t *)&addr->sin6_addr;
   uint32_t *from = (uint32_t *)src;
   target[0] = (((uint64_t)(htonl(from[0]))) << 32)
             +   (uint64_t)(htonl(from[1]));
   target[1] = (((uint64_t)(htonl(from[2]))) << 32)
             +   (uint64_t)(htonl(from[3]));
}
