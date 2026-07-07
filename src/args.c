#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include "../include/args.h"
#include "../include/types.h"

void print_configuration(struct pcat_config *config) {
  printf("Configuration:\n");
  printf("  Output file: %s\n", config->output_file);
  printf("  Source address: %s\n", config->src_address);
  printf("  Destination address: %s\n", config->dest_address);
  printf("  Scan range: %s\n", config->scan_range);
  printf("  Source port: %d\n", config->src_port);
  printf("  Destination port: %d\n", config->dest_port);
  printf("  Protocol: %d\n", config->protocol);
  printf("  Verbosity: %d\n", config->verbosity);
  printf("  Mode: %d\n", config->mode);
  printf("  Scan: %d\n", config->scan);
  printf("  Max connections: %d\n", config->max_connections);
  printf("  Keep open: %d\n", config->keep_open);
}

void default_configuration(struct pcat_config *config) {
  memset(config->output_file, 0, sizeof(config->output_file));
  memset(config->src_address, 0, sizeof(config->src_address));
  memset(config->dest_address, 0, sizeof(config->dest_address));
  memset(config->scan_range, 0, sizeof(config->scan_range));
  config->src_port = 0;
  config->dest_port = 1337;
  config->protocol = PROTOCOL_TCP;
  config->verbosity = 0;
  config->mode = MODE_CONNECT;
  config->scan = SCAN_SYN;
  config->max_connections = 5;
  config->keep_open = false;
}

void print_usage() {
  printf("Usage:\n");
  printf("  pcat [OPTION]... [ADDRESS]... [PORT]...\n");
  printf("Synopsis:\n");
  printf("  A versatile command-line network utility used for debugging, file transfer, and arbitrary connections.\n");
  printf("Description:\n");
  printf("  p(acket)(con)cat(enate) is a minimalistic, versatile network utility that can be used to create TCP and UDP connections.\n");
  printf("  It can be used for network debugging & diagnostics, port scanning, security testing, file transfers, and just about anything else involving networking.\n");
  printf("  Details surrounding possible options can be found in the sections below:\n");
  printf("General Options:\n");
  printf("  -h, --help                   Prints this message.\n");
  printf("  -o, --output <filename>      Outputs received data to a file.\n");
  printf("  -s, --source-port <port>     Specifies a port to bind to.\n");
  printf("  -a, --source-addr <address>  Specifies an address to use.\n");
  printf("  -m, --max-connections <n>    Allows <n> simultaneous connections.\n");
  printf("  -p, --ping <n>               Sends <n> pings to the destination, and returns the results of those pings.\n"); 
  printf("  -l, --listen                 Binds and listens for incoming connections.\n");
  printf("  -k, --keep-open              Allows multiple connections to be established in listen mode.\n");
  printf("  -v, --verbose                Increases verbosity level, can be specified for a maximum of three times for maximum verbosity.\n");
  printf("  -u, --udp                    Uses the UDP protocol instead of the default TCP.\n");
  printf("  -c, --chat                   Creates a minimalistic chat server. Messages sent by connected clients will be echoed to the rest.\n");
  printf("  -z, --config                 Prints the configuration.\n");
  printf("Scanning Options:\n");
  printf("  -sS, --scan-syn              Starts a TCP SYN scan on ports 1-65536 on the host. May require privileges.\n");
  printf("  -sU, --scan-udp              Starts a UDP scan on ports 1-65536 on the host. May require privileges.\n");
  printf("  -sT, --scan-tcp              Starts a TCP connect scan on ports 1-65536 on the host. Generally inferior to TCP SYN scans, but does not require privileges.\n");
  printf("  -r, --port-range <n1-n2>     Defines the port range from <n1> to <n2>. If a scan option was specified, the port range will be used for scanning instead of defaulting to scanning all the ports.\n");
  printf("Addendum:\n"); 
  printf("  In listen mode, the port and address are optional parameters. If the port is not specified, the default is 1337. If the address is not specified, it defaults to listening on all avaliable addresses.\n");
  printf("  In connect mode, however, the address and port are required parameters. Not specifying them will cause the program to exit prematurely and return an error.\n");
  printf("  Moreover, connect mode does not need to specified at all, it is inferred unless the listen option is specified.\n");
  printf("  The address argument works for domains, hostnames and ordinary IP addresses.\n");
  printf("  The source port option must not be confused with the port argument. The source port option specifies the port where traffic originates from, not the destination.\n");
  printf("  Similarly, the source address option specifies the address where traffic originates from, not where traffic is headed.\n");
  printf("  If listen mode is specified, the specified source port and address do not change anything.\n");
  printf("  Note that scanning options treat the character after the '-s' as an argument to the option. A space is needed if specifying further options.\n");
}

void parse_args(int argc, char **argv, struct pcat_config *config) {
  int opt; bool print_conf = false; bool parsing = true;

  struct option long_options[] = {
    {"help",              no_argument,             0, 'h'},
    {"output",            required_argument,       0, 'o'},
    {"source-port",       required_argument,       0, 's'},
    {"source-addr",       required_argument,       0, 'a'},
    {"max-connections",   required_argument,       0, 'm'},
    {"ping",              required_argument,       0, 'p'},
    {"listen",            no_argument,             0, 'l'},
    {"keep-open",         no_argument,             0, 'k'},
    {"verbose",           no_argument,             0, 'v'},
    {"udp",               no_argument,             0, 'u'},
    {"chat",              no_argument,             0, 'c'},
    {"config",            no_argument,             0, 'z'},
    {"scan-syn",          required_argument,       0,  1 },
    {"scan-udp",          required_argument,       0,  2 },
    {"scan-tcp",          required_argument,       0,  3 },
    {"port-range",        required_argument,       0, 'r'},
    {0,                   0,                       0,  0 }
  };

  while (parsing) {
    opt = getopt_long(argc, argv, "ho:s:a:m:p:lkvuczs:r:", long_options, NULL);
    switch (opt) {
      case 'h':
        print_usage();
        exit(0); break;
      case 'o':
        memset(config->output_file, 0, sizeof(config->output_file));
        strcpy(config->output_file, optarg);
        break;
      case 'p':
        config->src_port = strtol(optarg, NULL, 10); break;
      case 'a':
        memset(config->src_address, 0, sizeof(config->src_address));
        strcpy(config->src_address, optarg);
        break;
      case 'm':
        config->max_connections = strtol(optarg, NULL, 10); break;
      case 'l':
        if (config->mode == MODE_CHAT) break;
        config->mode = MODE_LISTEN; break;
      case 'k':
        config->keep_open = true; break;
      case 'v':
        if (config->verbosity < 3) 
          config->verbosity += 1; 
        break;
      case 'u':
        config->protocol = PROTOCOL_UDP; break;
      case 'i':
        config->protocol = PROTOCOL_ICMP; 
        config->mode = MODE_PING; 
        break;
      case 'c':
        config->mode = MODE_CHAT; break;
      case 'z':
        print_conf = true; break;
      case 's':
        if (strcmp(optarg, "S") == 0) {
          config->mode = MODE_SCAN;
          config->scan = SCAN_SYN;
        } else if (strcmp(optarg, "U") == 0) {
          config->mode = MODE_SCAN;
          config->scan = SCAN_UDP;
        } else if (strcmp(optarg, "T") == 0) {
          config->mode = MODE_SCAN;
          config->scan = SCAN_TCP;
        } 
        break;
      case 1:
        config->mode = MODE_SCAN;
        config->scan = SCAN_SYN;
        break;
      case 2:
        config->mode = MODE_SCAN;
        config->scan = SCAN_UDP;
        break;
      case 3:
        config->mode = MODE_SCAN;
        config->scan = SCAN_TCP;
        break;
      case 'r':
        memset(config->scan_range, 0, sizeof(config->scan_range));
        strcpy(config->scan_range, optarg);
        break;
      case '?':
        fprintf(stderr, "pcat: Invalid option passed!\n");
        print_usage(); 
        exit(1); break;
      case ':':
        fprintf(stderr, "pcat: Invalid argument '%s' passed!", optarg);
        print_usage(); 
        exit(1); break;
      case -1:
        if ((argc - 2) != optind && config->mode == MODE_CONNECT) {
          fprintf(stderr, "pcat: An address and a port must be specified in connect mode.\n");
          exit(1); break;
        } else if ((argc - 2) == optind && config->mode == MODE_CONNECT) {
          strcpy(config->dest_address, argv[optind]);
          if (isdigit(argv[optind+1][0]) != 0)
            config->dest_port = strtol(argv[optind+1], NULL, 10);
          else
            fprintf(stderr, "pcat: The port argument must contain a positive integer.\n");
          parsing = false; break;
        }
        // From this point, we must be in listen or chat mode:
        for (int i = optind; i < argc; i++) {
          // If it contains a dot (IP address) or an ASCII character (hostname/domain):
          if (strchr(argv[i], '.') != NULL || isdigit(argv[i][0]) == 0) 
            strcpy(config->dest_address, argv[i]);
          else
            config->dest_port = strtol(argv[i], NULL, 10);
        }
        parsing = false; 
        break;
    }
  }
  if (print_conf) print_configuration(config);
}


