#include <v6scan/common.h>

uint32_t OPTIONS      = 0;
uint32_t WAIT_TO_SEC  = 1;
uint32_t WAIT_TO_NSEC = 0;//500000000;
uint32_t ICMP_DELAY   = 1;
uint32_t MAX_ICMP     = 0;
uint32_t FILENUM      = 0;
uint32_t WINDOW       = 4;
uint8_t  EXIT_CODE    = 0;
uint8_t  THREAD_EXIT  = 0;
uint8_t  VERBOSE      = 1;


pcap_t *handle;

pthread_mutex_t filelock         = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stdoutlock       = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t sqlqueuelock     = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pktprocqueuelock = PTHREAD_MUTEX_INITIALIZER;

char dev[256] = {0};
char directory[256] = {0};

void makefilepath(char *filepath, const char *name, const char *ext, int len, int filenum)
{
   char filename[256];
   sprintf(filename, "/%s%02d.%s", name, filenum, ext);
   strncpy(filepath, directory, len);
   strncat(filepath, filename, len-strlen(filepath));
}
