#ifndef SCAN_H
#define SCAN_H

#include "../include/types.h"

void scan_syn(struct pcat_config *config);
void scan_udp(struct pcat_config *config);
void scan_tcp(struct pcat_config *config);

#endif 
