/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#ifndef _PING_H
#define _PING_H

#include <stdbool.h>

#include "DHT.h"
#include "net_crypto.h"
#include "packets.h"
#include "network.h"
#include "util.h"

void init_ping();
uint64_t add_ping(IP_Port ipp);
bool is_pinging(IP_Port ipp, uint64_t ping_id);
int send_ping_request(IP_Port ipp, clientid_t* client_id);
int send_ping_response(IP_Port ipp, clientid_t* client_id, uint64_t ping_id);
<<<<<<< HEAD
int handle_ping_request(uint8_t* packet, uint32_t length, IP_Port source);
int handle_ping_response(uint8_t* packet, uint32_t length, IP_Port source);

#endif /* _PING_H */
=======
int handle_ping_request(IP_Port source, uint8_t* packet, uint32_t length);
int handle_ping_response(IP_Port source, uint8_t* packet, uint32_t length);
>>>>>>> upstream/master
