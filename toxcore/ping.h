/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>

void *new_ping(void);
void kill_ping(void *ping);
uint64_t add_ping(void *ping, IP_Port ipp);
bool is_pinging(void *ping, IP_Port ipp, uint64_t ping_id);
int send_ping_request(void *ping, Net_Crypto *c, IP_Port ipp, uint8_t *client_id);
int send_ping_response(Net_Crypto *c, IP_Port ipp, uint8_t *client_id, uint64_t ping_id);
int handle_ping_request(void *object, IP_Port source, uint8_t *packet, uint32_t length);
int handle_ping_response(void *object, IP_Port source, uint8_t *packet, uint32_t length);
