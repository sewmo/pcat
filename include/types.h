#ifndef TYPES_H
#define TYPES_H

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#define PROTOCOL_TCP  1
#define PROTOCOL_UDP  2
#define PROTOCOL_ICMP 3

#define MODE_CONNECT 1
#define MODE_LISTEN  2
#define MODE_CHAT    3
#define MODE_PING    4
#define MODE_SCAN    5

#define SCAN_SYN 1
#define SCAN_UDP 2
#define SCAN_TCP 3

struct pcat_config {
  char output_file[64];
  char src_address[64];
  char dest_address[64];
  char scan_range[64];
  int max_connections;
  int src_port;
  int dest_port;
  int protocol;
  int verbosity;
  int mode;
  int scan;
  bool keep_open;
};

#endif
