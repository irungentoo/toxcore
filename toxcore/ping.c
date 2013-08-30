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

    // Loop through buffer, oldest first.
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

    /* Remove oldest ping if full buffer. */
    if (png->num_pings == PING_NUM_MAX) {
        png->num_pings--;
        png->pos_pings = (png->pos_pings + 1) % PING_NUM_MAX;
    }

    /* Insert new ping at end of list. */
    p = (png->pos_pings + png->num_pings) % PING_NUM_MAX;

    png->pings[p].ipp       = ipp;
    png->pings[p].timestamp = now();
    png->pings[p].id        = random_64b();

    png->num_pings++;
    return png->pings[p].id;
}

bool is_pinging(void *ping, IP_Port ipp, uint64_t ping_id)    // O(n) TODO: Replace this with something else.
{
    PING *png = ping;

    if (ipp.ip.uint32 == 0 && ping_id == 0)
        return false;

    size_t i, id;

    remove_timeouts(ping);

    for (i = 0; i < png->num_pings; i++) {
        id = (png->pos_pings + i) % PING_NUM_MAX;

        /* ping_id = 0 means match any id. */
        if ((ipp_eq(png->pings[id].ipp, ipp) || ipp.ip.uint32 == 0) && (png->pings[id].id == ping_id || ping_id == 0)) {
            return true;
        }
    }

    return false;
}

#define DHT_PING_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(uint64_t) + ENCRYPTION_PADDING)

int send_ping_request(void *ping, Net_Crypto *c, IP_Port ipp, uint8_t *client_id)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (is_pinging(ping, ipp, 0) || id_eq(client_id, c->self_public_key))
        return 1;

    // Generate random ping_id.
    ping_id = add_ping(ping, ipp);

    pk[0] = NET_PACKET_PING_REQUEST;
    id_cpy(pk + 1, c->self_public_key);     // Our pubkey
    random_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data(client_id,
                      c->self_secret_key,
                      pk + 1 + CLIENT_ID_SIZE,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(c->lossless_udp->net->sock, ipp, pk, sizeof(pk));
}

int send_ping_response(Net_Crypto *c, IP_Port ipp, uint8_t *client_id, uint64_t ping_id)
{
    uint8_t   pk[DHT_PING_SIZE];
    int       rc;

    if (id_eq(client_id, c->self_public_key))
        return 1;

    pk[0] = NET_PACKET_PING_RESPONSE;
    id_cpy(pk + 1, c->self_public_key);     // Our pubkey
    random_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate random nonce

    // Encrypt ping_id using recipient privkey
    rc = encrypt_data(client_id,
                      c->self_secret_key,
                      pk + 1 + CLIENT_ID_SIZE,
                      (uint8_t *) &ping_id, sizeof(ping_id),
                      pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != sizeof(ping_id) + ENCRYPTION_PADDING)
        return 1;

    return sendpacket(c->lossless_udp->net->sock, ipp, pk, sizeof(pk));
}

int handle_ping_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    int        rc;
    uint64_t   ping_id;

    if (length != DHT_PING_SIZE)
        return 1;

    if (id_eq(packet + 1, dht->c->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data(packet + 1,
                      dht->c->self_secret_key,
                      packet + 1 + CLIENT_ID_SIZE,
                      packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    // Send response
    send_ping_response(dht->c, source, packet + 1, ping_id);
    add_toping(dht, packet + 1, source);

    return 0;
}

int handle_ping_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    int       rc;
    uint64_t  ping_id;

    if (length != DHT_PING_SIZE)
        return 1;

    if (id_eq(packet + 1, dht->c->self_public_key))
        return 1;

    // Decrypt ping_id
    rc = decrypt_data(packet + 1,
                      dht->c->self_secret_key,
                      packet + 1 + CLIENT_ID_SIZE,
                      packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                      sizeof(ping_id) + ENCRYPTION_PADDING,
                      (uint8_t *) &ping_id);

    if (rc != sizeof(ping_id))
        return 1;

    /* Make sure ping_id is correct. */
    if (!is_pinging(dht->ping, source, ping_id))
        return 1;

    // Associate source ip with client_id
    addto_lists(dht, source, packet + 1);
    return 0;
}
