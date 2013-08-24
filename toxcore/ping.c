/*
 * ping.c -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"
#include "net_crypto.h"
#include "packets.h"
#include "network.h"
#include "util.h"

#define PING_NUM_MAX 256
#define PING_TIMEOUT 5 // 5s

typedef struct {
    IP_Port  ipp;
    uint64_t id;
    uint64_t timestamp;
} pinged_t;

typedef struct {
    pinged_t    pings[PING_NUM_MAX];
    size_t      num_pings;
    size_t      pos_pings;
} PING;

void *new_ping(void)
{
    return calloc(1, sizeof(PING));
}

void kill_ping(void *ping)
{
    free(ping);
}

static bool is_timeout(uint64_t time)
{
    return (time + PING_TIMEOUT) < now();
}

static void remove_timeouts(void *ping)    // O(n)
{
    PING *png = ping;
    size_t i, id;
    size_t new_pos = png->pos_pings;
    size_t new_num = png->num_pings;

    // Loop through buffer, oldest first
    for (i = 0; i < png->num_pings; i++) {
        id = (png->pos_pings + i) % PING_NUM_MAX;

        if (is_timeout(png->pings[id].timestamp)) {
            new_pos++;
            new_num--;
        }
        // Break here because list is sorted.
        else {
            break;
        }
    }

    png->num_pings = new_num;
    png->pos_pings = new_pos % PING_NUM_MAX;
}

uint64_t add_ping(void *ping, IP_Port ipp)  // O(n)
{
    PING *png = ping;
    size_t p;

    remove_timeouts(ping);

    // Remove oldest ping if full buffer
    if (png->num_pings == PING_NUM_MAX) {
        png->num_pings--;
        png->pos_pings = (png->pos_pings + 1) % PING_NUM_MAX;
    }

    // Insert new ping at end of list
    p = (png->pos_pings + png->num_pings) % PING_NUM_MAX;

    png->pings[p].ipp       = ipp;
    png->pings[p].timestamp = now();
    png->pings[p].id        = random_64b();

    png->num_pings++;
    return png->pings[p].id;
}

bool is_pinging(void *ping, IP_Port ipp, uint64_t ping_id)    // O(n) TODO: replace this with something else.
{
    PING *png = ping;

    if (ipp.ip.i == 0 && ping_id == 0)
        return false;

    size_t i, id;

    remove_timeouts(ping);

    for (i = 0; i < png->num_pings; i++) {
        id = (png->pos_pings + i) % PING_NUM_MAX;

        // ping_id = 0 means match any id
        if ((ipp_eq(png->pings[id].ipp, ipp) || ipp.ip.i == 0) && (png->pings[id].id == ping_id || ping_id == 0)) {
            return true;
        }
    }

    return false;
}

int send_ping_request(void *ping, Net_Crypto *c, IP_Port ipp, clientid_t *client_id)
{
    pingreq_t pk;
    int       rc;
    uint64_t  ping_id;

    if (is_pinging(ping, ipp, 0) || id_eq(client_id, (clientid_t *)c->self_public_key))
        return 1;

    // Generate random ping_id
    ping_id = add_ping(ping, ipp);

    pk.packet_id = NET_PACKET_PING_REQUEST;
    id_cpy(&pk.client_id, (clientid_t *)c->self_public_key);     // Our pubkey
    random_nonce((uint8_t *) &pk.nonce); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data((uint8_t *) client_id,
                      c->self_secret_key,
                      (uint8_t *) &pk.nonce,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      (uint8_t *) &pk.ping_id);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(c->lossless_udp->net->sock, ipp, (uint8_t *) &pk, sizeof(pk));
}

int send_ping_response(Net_Crypto *c, IP_Port ipp, clientid_t *client_id, uint64_t ping_id)
{
    pingres_t pk;
    int       rc;

    if (id_eq(client_id, (clientid_t *)c->self_public_key))
        return 1;

    pk.packet_id = NET_PACKET_PING_RESPONSE;
    id_cpy(&pk.client_id, (clientid_t *)c->self_public_key);     // Our pubkey
    random_nonce((uint8_t *) &pk.nonce); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data((uint8_t *) client_id,
                      c->self_secret_key,
                      (uint8_t *) &pk.nonce,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      (uint8_t *) &pk.ping_id);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(c->lossless_udp->net->sock, ipp, (uint8_t *) &pk, sizeof(pk));
}

int handle_ping_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    pingreq_t *p = (pingreq_t *) packet;
    int        rc;
    uint64_t   ping_id;

    if (length != sizeof(pingreq_t) || id_eq(&p->client_id, (clientid_t *)dht->c->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data((uint8_t *) &p->client_id,
                      dht->c->self_secret_key,
                      (uint8_t *) &p->nonce,
                      (uint8_t *) &p->ping_id,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Send response
    send_ping_response(dht->c, source, &p->client_id, ping_id);
    add_toping(dht, (uint8_t *) &p->client_id, source);

    return 0;
}

int handle_ping_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    pingres_t *p = (pingres_t *) packet;
    int       rc;
    uint64_t  ping_id;

    if (length != sizeof(pingres_t) || id_eq(&p->client_id, (clientid_t *)dht->c->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data((uint8_t *) &p->client_id,
                      dht->c->self_secret_key,
                      (uint8_t *) &p->nonce,
                      (uint8_t *) &p->ping_id,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Make sure ping_id is correct
    if (!is_pinging(dht->ping, source, ping_id))
        return 1;

    // Associate source ip with client_id
    addto_lists(dht, source, (uint8_t *) &p->client_id);
    return 0;
}
