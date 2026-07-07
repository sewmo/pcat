#ifndef FUNCS_H
#define FUNCS_H

#include "types.h"

void save_to_file(char *file, char *buf, int len);
void send_all(int fd, char *buf, int len);
int create_connect_socket(struct pcat_config *config);
int create_listen_socket(struct pcat_config *config);
void process_listen(struct pcat_config *config, int sockfd);
void process_connect(struct pcat_config *config, int sockfd);

#endif
