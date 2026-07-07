#ifndef ARGS_H
#define ARGS_H

#include "types.h"

void print_usage();
void default_configuration(struct pcat_config *config);
void parse_args(int argc, char **argv, struct pcat_config *config);

#endif
