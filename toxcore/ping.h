/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */
#ifndef __PING_H__
#define __PING_H__

#include <stdbool.h>

#ifndef __PING_C__
typedef struct PING PING;
#endif

/* Add nodes to the toping list.
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_toping(PING *ping, uint8_t *client_id, IP_Port ip_port);
void do_toping(PING *ping);

PING *new_ping(DHT *dht, Net_Crypto *c);
void kill_ping(PING *ping);

int send_ping_request(PING *ping, IP_Port ipp, uint8_t *client_id);

#endif /* __PING_H__ */
