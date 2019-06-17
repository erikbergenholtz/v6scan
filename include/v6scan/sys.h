#ifndef V6SCAN_SYS_H
#define V6SCAN_SYS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <pcap.h>

#include <v6scan/common.h>
#include <v6scan/icmp.h>

#define FATAL "[\033[1;91mFATAL\033[0m]"
#define WARN  "[\033[1;91mWARN\033[0m]"
#define INFO  "[\033[1;93mINFO\033[0m]"
#define OK    "[\033[1;92mOK\033[0m]"
#define DEBUG "[\033[1;94mDEBUG\033[0m]"

void fatal(const char *, ...) __attribute__((noreturn));
void warning(const char *, ...);
void info(const char *, ...);
void ok(const char *, ...);
void debug(const char *, ...);
void signalhandler(int);

#endif
