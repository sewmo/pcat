#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include "../include/funcs.h"

/* INFO: Appends the specified buffer (buf) of length (len) to the file (file). */
void save_to_file(char *file, char *buf, int len) {
  FILE *stream;
  stream = fopen(file, "a");
  if (fwrite(buf, 1, len, stream) == 0) {
    if (ferror(stream) != 0) {
      fprintf(stderr, "pcat: Failed to write to file.\n");
      exit(2);
    } 
  }
  fclose(stream);
}

/* INFO: Sends the specified buffer (buf) of length (len) to the socket (fd). */
void send_all(int fd, char *buf, int len) {
  size_t bytes_left = len;
  ssize_t bytes_sent;
  const char *ptr = (const char *)buf;

  while (bytes_left > 0) {
    bytes_sent = send(fd, ptr, bytes_left, 0);
    if (bytes_sent < 0) {
      fprintf(stderr, "pcap: Could not send bytes.\n");
      perror("(send)");
      exit(2);
    }
    bytes_left -= bytes_sent;
    ptr += bytes_sent;
  }
}

/* INFO: Returns a socket file descriptor that is actively connected to the specified destination address and port. */
int create_connect_socket(struct pcat_config *config) {
  struct sockaddr_in sockaddr;
  struct addrinfo hints, *servinfo, *p;
  struct in_addr addr;
  char servport[64];
  int rv; int sockfd;
    
  bool bind_sock = false;
  bool src_port_exists = (config->src_port != 0) ? true : false;
  bool src_addr_exists = (config->src_address[0] != 0) ? true : false;
  bool src_addr_ipv6 = (strchr(config->src_address, ':') != NULL) ? true : false;

  if (src_port_exists || src_addr_exists) bind_sock = true;

  if (bind_sock) {
    sockaddr.sin_port = htons(config->src_port);
    if (src_addr_ipv6) sockaddr.sin_family = AF_INET6;
    else sockaddr.sin_family = AF_INET;

    if (src_addr_exists) {
      inet_aton(config->src_address, &addr);
      sockaddr.sin_addr = addr;
    } else {
      sockaddr.sin_addr.s_addr = INADDR_ANY;
    }
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  if (config->protocol == PROTOCOL_TCP) hints.ai_protocol = IPPROTO_TCP;
  else if (config->protocol == PROTOCOL_UDP) hints.ai_protocol = IPPROTO_UDP;
  
  snprintf(servport, sizeof(servport), "%d", config->dest_port);

  if ((rv = getaddrinfo(config->dest_address, servport, &hints, &servinfo)) != 0) {
    fprintf(stderr, "pcat: Failed to resolve address %s\n(%s)\n", config->dest_address, gai_strerror(rv));
    exit(1);
  }

  struct sockaddr_in *servaddr;
  char dest[64] = {0};
  int port;

  for (p = servinfo; p != NULL; p = p->ai_next) {
    if (config->protocol == PROTOCOL_TCP) sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    else if (config->protocol == PROTOCOL_UDP) sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (bind_sock) {
      if (bind(sockfd, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
        printf("pcat: Failed to bind socket to address %s and port %d.\n", config->src_address, config->src_port);
        printf("pcat: The source address and source port will be determined by the operating system.\n");
        perror("pcat: bind");
      }
    }

    servaddr = (struct sockaddr_in *)servinfo->ai_addr;
    port = ntohs(servaddr->sin_port);

    memset(dest, 0, sizeof(dest));
    strcpy(dest, inet_ntoa(servaddr->sin_addr));

    if (config->verbosity >= 1) printf("pcat: Attempting connection to %s.\n", dest);
    if (connect(sockfd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
      printf("pcat: Failed to connect to %s:%d.\n", dest, port);
      perror("pcat: connect");
      close(sockfd);
      continue;
    }
    break;
  }

  if (p == NULL) {
    fprintf(stderr, "pcat: All attempts made to connect to %s:%d have failed.\n", dest, port);
    exit(2);
  }
  if (config->verbosity >= 1) printf("pcat: Successfully connected to %s:%d.\n", dest, port);

  freeaddrinfo(servinfo);
  return sockfd;
}

/* INFO: Returns a socket file descriptor that is actively listening for connections. */
int create_listen_socket(struct pcat_config *config) {
  struct sockaddr_in sockaddr;
  bool dest_addr_exists = (config->dest_address[0] != 0) ? true : false;
  int sockfd; int type; int protocol;
  int domain = AF_INET;
  if (config->protocol == PROTOCOL_UDP) {
    type = SOCK_DGRAM;
    protocol = IPPROTO_UDP;
  } else if (config->protocol == PROTOCOL_TCP) {
    type = SOCK_STREAM;
    protocol = IPPROTO_TCP;
  }
  sockfd = socket(domain, type, protocol);

  sockaddr.sin_family = AF_INET;
  sockaddr.sin_port = htons(config->dest_port);

  if (dest_addr_exists) {
    struct in_addr addr;
    inet_aton(config->dest_address, &addr);
    sockaddr.sin_addr = addr;
  } else sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  
  if (bind(sockfd, (const struct sockaddr *)&sockaddr, sizeof(sockaddr)) != 0) {
    fprintf(stderr, "pcat: Failed to bind socket.\n");
    perror("(bind)");
    exit(2);
  }

  if (listen(sockfd, config->max_connections) != 0) {
    fprintf(stderr, "pcat: Failed to put socket into listening mode.\n");
    perror("(listen)");
    exit(2);
  }
  if (config->verbosity >= 1) printf("pcat: Listening on %s:%d.\n", inet_ntoa(sockaddr.sin_addr), config->dest_port);

  return sockfd;
}

/* INFO: Handles the process of a listening socket. If MODE_CHAT is specified in the configuration, the process will act as a chat application. */
void process_listen(struct pcat_config *config, int sockfd) {
  int count = 2;
  int send_len = 0; 
  int newsock, rv, nfds;
  if (config->keep_open) 
    nfds = config->max_connections + 2;
  else nfds = 3;
  char recv_buf[2048] = {0};
  char send_buf[2048] = {0};
  socklen_t addrlen;
  struct pollfd pfds[nfds];
  struct sockaddr_in newaddr;
  bool save_output = (config->output_file[0] != 0) ? true : false;

  for (int i = 0; i < nfds; i++) {
    pfds[i].fd = -1;
    pfds[i].events =  POLLIN;
    pfds[i].revents = 0;
  }

  pfds[0].fd = STDIN_FILENO;
  pfds[1].fd = sockfd;

  while (true) {
    send_len = 0;
    rv = poll(pfds, nfds, -1);
    if (rv == -1) {
      fprintf(stderr, "pcat: Poll failed.\n");
      perror("(poll)");
      exit(2);
    }

    // New standard input buffer pending;
    if (pfds[0].revents & POLLIN) {
      if (config->verbosity >= 3) 
        printf("pcat: Reading from standard input.\n");
      memset(send_buf, 0, sizeof(send_buf));
      send_len = read(STDIN_FILENO, send_buf, sizeof(send_buf));
    }

    // New connection pending;
    if (pfds[1].revents & POLLIN) {
      addrlen = sizeof(newaddr);
      newsock = accept(sockfd, (struct sockaddr *)&newaddr, &addrlen);
      if (newsock == -1) {
        fprintf(stderr, "pcat: Failed to accept client.\n");
        perror("(accept)");
        exit(2);
      }
      if (config->verbosity >= 1) {
        char *ip = inet_ntoa(newaddr.sin_addr);
        printf("pcat: New connection from %s:%d.\n", ip, ntohs(newaddr.sin_port));
      }
      if (count >= nfds) {
        if (config->verbosity >= 1)
          printf("pcat: Rejecting client connection attempt - maximum connections reached.\n");
        count = nfds;
      } else {
        pfds[count].fd = newsock;
        pfds[count].events = POLLIN | POLLOUT;
        count++;
        if (config->verbosity >= 3) {
          printf("pcat: Added file descriptor %d to list, total file descriptors %d, list:\n", pfds[count-1].fd, count);
          for (int i = 0; i < count; i++) 
            printf("FD #%d: %d\n", i, pfds[i].fd);
        }
      }
    }

    for (int i = 2; i < count; i++) {
      if (pfds[i].fd == -1) continue;

      // Message from socket pending;
      if (pfds[i].revents & POLLIN) {
        if (config->verbosity >= 3)
          printf("pcat: Receiving message from client #%d.\n", i-1);
        memset(recv_buf, 0, sizeof(recv_buf));
        rv = recv(pfds[i].fd, recv_buf, sizeof(recv_buf), 0);
        if (rv == -1) {
          fprintf(stderr, "pcat: Error occured while receiving message from client #%d.\n", i-1);
          perror("(recv)");
          exit(2);
        } else if (rv == 0) {
          if (!config->keep_open) {
            if (config->verbosity >= 1)
              printf("pcat: Client disconnected.\n");
            return;
          }
          int fd_remove = pfds[i].fd;
          for (int j = i; j < count-1; j++) {
            pfds[j].fd = pfds[j+1].fd;
            pfds[j].events = pfds[j+1].events;
            pfds[j].revents = pfds[j+1].revents;
          }
          pfds[count-1].fd = -1;
          pfds[count-1].events = POLLIN;
          count--;
          if (config->verbosity >= 3) {
            printf("pcat: Client disconnected, removed file descriptor %d, total file descriptors %d, list:\n", fd_remove, count);
            for (int i = 0; i < count; i++) 
              printf("FD #%d: %d\n", i, pfds[i].fd);
          }
        }
  
        printf("%s", recv_buf);
        if (save_output)
          save_to_file(config->output_file, recv_buf, sizeof(recv_buf));

        if (config->mode == MODE_CHAT) {
          for (int j = 2; j < count; j++) {
            if (pfds[j].fd == -1) continue;
            else if (pfds[j].fd == pfds[i].fd) continue;

            if (pfds[j].revents & POLLOUT) {
              if (config->verbosity >= 3)
                printf("pcat: Echoing message to client #%d.\n", j-1);
              send_all(pfds[j].fd, recv_buf, sizeof(recv_buf));
            } else {
              if (config->verbosity >= 1) 
                printf("pcat: Could not echo message to client #%d.\n", j-1);
            }
          }
        }
      }

      // Message ready to be sent to socket is pending;
      if (send_len == 0) continue;

      if (pfds[i].revents & POLLOUT) {
        if (config->verbosity >= 3)
          printf("pcat: Sending message to client #%d.\n", i-1);
        send_all(pfds[i].fd, send_buf, sizeof(send_buf));
      } else {
        if (config->verbosity >= 1)
          printf("pcat: Could not send message to client #%d.\n", i-1);
      }
    }
  }
}

/* INFO: Handles the process of a connected socket. */
void process_connect(struct pcat_config *config, int sockfd) {
  int send_len = 0;
  char send_buf[2048] = {0};
  char recv_buf[2048] = {0};
  bool save_output = (config->output_file[0] != 0) ? true : false; 

  while (true) {
    // INFO: POLLIN = There is data to be read;
    // INFO: POLLOUT = Writing is now possible;
    struct pollfd pfds[2] = {0};
    pfds[0].fd = sockfd;
    pfds[0].events = POLLIN | POLLOUT;
    pfds[1].fd = STDIN_FILENO;
    pfds[1].events = POLLIN;

    int rv = poll(pfds, 2, -1);
    if (rv == -1) {
      fprintf(stderr, "pcat: Poll failed.\n");
      perror("(poll)");
      exit(2);
    }

    int sock_pollin = pfds[0].revents & POLLIN;
    int sock_pollout = pfds[0].revents & POLLOUT;
    int in_pollin = pfds[1].revents & POLLIN;

    if (sock_pollin) {
      memset(recv_buf, 0, sizeof(recv_buf));

      rv = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
      if (rv == -1) {
        fprintf(stderr, "pcat: Error occured while receiving message from server.\n");
        perror("(recv)");
        exit(2);
      } else if (rv == 0) {
        printf("pcat: Server has terminated the connection.\n");
        break;
      }

      printf("%s", recv_buf);
      if (save_output) 
        save_to_file(config->output_file, recv_buf, sizeof(recv_buf));
    }

    if (in_pollin) {
      memset(send_buf, 0, sizeof(send_buf));
      send_len = read(STDIN_FILENO, send_buf, sizeof(send_buf));
    }

    if (sock_pollout) {
      if (send_len != 0)
        send_all(sockfd, send_buf, send_len);
      send_len = 0;
    }
  }
}
