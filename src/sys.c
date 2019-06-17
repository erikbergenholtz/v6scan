#include <v6scan/sys.h>

void fatal(const char *msg, ...)
{
   if(VERBOSE >= Fatal)
   {
      fprintf(stderr, "%s ", FATAL);
      va_list args;
      va_start(args,msg);
      vfprintf(stderr,msg,args);
      va_end(args);
      fflush(stderr);
      pthread_mutex_unlock(&stdoutlock);
   }
   exit(2);
}

void warning(const char *msg, ...)
{
   if(VERBOSE >= Warning)
   {
      pthread_mutex_lock(&stdoutlock);
      fprintf(stderr, "%s ", WARN);
      va_list args;
      va_start(args,msg);
      vfprintf(stderr,msg,args);
      va_end(args);
      fflush(stderr);
      pthread_mutex_unlock(&stdoutlock);
   }
}

void info(const char *msg, ...)
{
   if(VERBOSE == Info)
   {
      pthread_mutex_lock(&stdoutlock);
      fprintf(stdout, "%s ", INFO);
      va_list args;
      va_start(args,msg);
      vfprintf(stdout,msg,args);
      va_end(args);
      fflush(stdout);
      pthread_mutex_unlock(&stdoutlock);
   }
}

void ok(const char *msg, ...)
{
   pthread_mutex_lock(&stdoutlock);
   fprintf(stdout,"%s ", OK);
   va_list args;
   va_start(args,msg);
   vfprintf(stdout,msg,args);
   va_end(args);
   fflush(stdout);
   pthread_mutex_unlock(&stdoutlock);
}

void debug(const char *msg, ...)
{
   if(OPTIONS & OPT_DBG)
   {
      pthread_mutex_lock(&stdoutlock);
      fprintf(stdout, "%s ", DEBUG);
      va_list args;
      va_start(args,msg);
      vfprintf(stdout,msg,args);
      va_end(args);
      fflush(stdout);
      pthread_mutex_unlock(&stdoutlock);
   }
}

void signalhandler(int signal)
{
   if(signal == SIGINT)
   {
      debug("Thread ID: %p\n", pthread_self());
      info("Caught ^C, exiting\n", INFO);
      THREAD_EXIT = 1;
      if(OPTIONS & OPT_SNIFF)
         pcap_breakloop(handle);
   }
   EXIT_CODE = 128+signal;
}
