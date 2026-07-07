#include <asm-generic/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include "../include/types.h"
#include "../include/scan.h"

/*
 TODO: Open <n> sockets, add them to pollfd array, start non-blocking connect, after limit is reached, poll. For each ready socket, determine result and close.
 TODO: Use epoll() for the system described above, instead of normal poll().
 TODO: Use /etc/services file for associating open ports with services.
*/

void scan_syn(struct pcat_config *config) {
  int sockfd = socket(AF_INET, SOCK_RAW, 0);

}

void scan_udp(struct pcat_config *config) {

}

void scan_tcp(struct pcat_config *config) {
  struct addrinfo hints, *servinfo, *p;
  int rv, port_min, port_max;
  
  printf("pcat: Initiating a TCP scan on address %s\n", config->dest_address);

  if (config->scan_range[0] == 0) {
    port_min = 1;
    port_max = 65536;
  } else {
    char *ptr = strtok(config->scan_range, "-");

    port_min = strtol(ptr, NULL, 10);
    while (ptr != NULL) {
      port_max = strtol(ptr, NULL, 10);
      ptr = strtok(NULL, "-");
    } 
  }

  if (port_max > 65536) port_max = 65536;
  if (port_min < 1)     port_min = 1;

  printf("pcat: Scan range: %d-%d\n", port_min, port_max);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_protocol = IPPROTO_TCP;

  if ((rv = getaddrinfo(config->dest_address, NULL, &hints, &servinfo)) != 0) {
    fprintf(stderr, "pcat: Failed to resolve address %s\n(%s)\n", config->dest_address, gai_strerror(rv));
    exit(1);
  }

  int n = 0;
  for (p = servinfo; p != NULL; p = p->ai_next) n++;

  struct addrinfo *nodes[n];
  printf("pcat: Found %d nodes for destination address\n", n);

  int i = 0;
  for (p = servinfo; p != NULL; p = p->ai_next) {
    nodes[i] = servinfo;
    i++;
  }

  int amount = port_max - port_min;

  for (int i = 0; i < n; i++) {
    struct timeval start, end, diff;
    struct sockaddr_storage addr;
    memcpy(&addr, nodes[i]->ai_addr, nodes[i]->ai_addrlen);
    bool ipv4 = (addr.ss_family == AF_INET);
    bool ipv6 = (addr.ss_family == AF_INET6);
    if (!ipv4 && !ipv6) {
      fprintf(stderr, "pcat: Failed to recognize node domain\n");
      exit(1);
    }
    
    int cnt = 0;
    int opens = 0;
    int timeout = 50;
    int limit = 1000;
    int pnums[limit];
    struct pollfd pfds[limit];
    for (int i = 0; i < limit; i++) {
      pfds[i].fd = -1;
      pfds[i].events = POLLOUT;
      pfds[i].revents = 0;
    }

    printf("pcat: Starting TCP scan for node %d\n", i);
    gettimeofday(&start, NULL);
    for (int port = port_min; port < port_max; port++) {
      int sockfd;
      if (ipv4) {
        ((struct sockaddr_in *)&addr)->sin_port = htons(port);
      } else if (ipv6) {
        ((struct sockaddr_in6 *)&addr)->sin6_port = htons(port);
      }  

      if (ipv4) {
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      } else if (ipv6) {
        sockfd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
      }

      if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) | O_NONBLOCK) == -1) {
        fprintf(stderr, "pcat: Failed to set socket to non-blocking, errno = %d\n", errno);
        exit(1);
      }

      struct sockaddr_in sockaddr;
      errno = 0;
      if (connect(sockfd, (struct sockaddr *)&addr, sizeof(sockaddr)) == 0) {
        opens++;
        printf("pcat: Port %d - Open\n", port);
      } else {
        if (errno != EINPROGRESS) {
          if (config->verbosity >= 1)
            printf("pcat: Port %d - Closed\n", port);
        } else { 
          pnums[cnt] = port;
          pfds[cnt].fd = sockfd;
          cnt++;
        }
      }
      if (cnt >= limit || port == port_max-1) {
        cnt = 0;
        if (poll(pfds, limit, timeout) < 0) {
          fprintf(stderr, "pcat: Polling failed unexpectedly!\n");
          perror("(poll)");
          exit(1);
        }
        
        for (int i = 0; i < limit; i++) {
          if (pfds[i].fd == -1) continue;

          if (pfds[i].revents & POLLOUT) {
            int err;
            socklen_t len = sizeof(err);
            getsockopt(pfds[i].fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (err == 0) {
              opens++;
              printf("pcat: Port %d - Open (Async success)\n", pnums[i]);
            } else {
              if (config->verbosity >= 1)
                printf("pcat: Port %d - Closed (%s)\n", pnums[i], strerror(err));
            }
          } else {
            if (config->verbosity >= 1)
              printf("pcat: Port %d - Closed (Poll timeout)\n", pnums[i]);
          }

          close(pfds[i].fd);
          pfds[i].fd = -1;
          pfds[i].revents = 0;
        }
      }
    }
    gettimeofday(&end, NULL);
    timersub(&end, &start, &diff);
    printf("pcat: %d Open ports - %d Closed ports\n", opens, amount-opens);
    printf("pcat: Elapsed time: %lds, %ldms\n", (long)diff.tv_sec, (long)diff.tv_usec); 

  }
  freeaddrinfo(servinfo);
}
