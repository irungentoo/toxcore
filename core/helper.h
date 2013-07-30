#ifndef _HELPER_H_
#define _HELPER_H_

#include "network.h"

#include <time.h>
#include <inttypes.h>

int set_ip_port(const char *ip, short port, IP_Port *dest);

uint32_t get_random_number(uint32_t _max);

void memadd(uint8_t *dest, uint16_t from, const uint8_t *source, uint16_t size);

#endif /* _HELPER_H_ */
