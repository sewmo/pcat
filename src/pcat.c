#include "../include/funcs.h"
#include "../include/args.h"
#include "../include/scan.h"

/* 
   TODO: Create UDP listening socket server.
   TODO: Send ICMP packets.
   TODO: Create port scanning utility.
*/   

int main(int argc, char **argv) 
{
  struct pcat_config config;
  default_configuration(&config);
  parse_args(argc, argv, &config);

  switch (config.mode) {
    case MODE_CONNECT: {
      int sockfd = create_connect_socket(&config);
      process_connect(&config, sockfd);
      break;
    }
    case MODE_LISTEN: {
      int sockfd = create_listen_socket(&config);
      process_listen(&config, sockfd);
      break;
    }
    case MODE_CHAT: {
      int sockfd = create_listen_socket(&config);
      process_listen(&config, sockfd);
      break;
    }
    case MODE_PING: {
      break;
    }
    case MODE_SCAN: {
      switch (config.scan) {
        case SCAN_SYN:
          scan_syn(&config);
          break;
        case SCAN_TCP:
          scan_tcp(&config);
          break;
        case SCAN_UDP:
          scan_udp(&config);
          break;
        default:
          break;
      }
      break;
    }
  }

  return 0;
}

