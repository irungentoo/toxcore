
#include "rendezvous.h"
#include "network.h"
#include "net_crypto.h"
#include "assoc.h"
#include "util.h"

/* network: packet id */
#define NET_PACKET_RENDEZVOUS 8

/* 30 seconds */
#define RENDEZVOUS_SEND_AGAIN 30U

/* stored entries */
#define RENDEZVOUS_STORE_SIZE 8

/* total len of hash over input/time */
#define HASHLEN crypto_hash_sha512_BYTES

typedef struct RendezVousPacket {
    uint8_t  type;
    uint8_t  hash_unspecific_half[HASHLEN / 2];
    uint8_t  hash_specific_half[HASHLEN / 2];
    uint8_t  target_id[crypto_box_PUBLICKEYBYTES];
} RendezVousPacket;

typedef struct {
    uint64_t           recv_at;
    IP_Port            ipp;

    RendezVousPacket   packet;

    uint8_t            match;
    uint64_t           sent_at;
} RendezVous_Entry;

typedef struct RendezVous {
    Assoc             *assoc;
    Networking_Core   *net;

    uint8_t           *self_public;
    uint64_t           block_store_until;

    uint64_t           timestamp;
    uint64_t           publish_starttime;
    RendezVous_callbacks   functions;
    void                  *data;
    uint8_t            hash_unspecific_complete[HASHLEN];
    uint8_t            hash_specific_half[HASHLEN / 2];

    RendezVous_Entry   store[RENDEZVOUS_STORE_SIZE];
} RendezVous;

static void publish(RendezVous *rendezvous)
{
    RendezVousPacket packet;
    // uint8_t packet[1 + HASHLEN + crypto_box_PUBLICKEYBYTES];
    packet.type = NET_PACKET_RENDEZVOUS;
    memcpy(packet.hash_unspecific_half, rendezvous->hash_unspecific_complete, HASHLEN / 2);
    memcpy(packet.hash_specific_half, rendezvous->hash_specific_half, HASHLEN / 2);
    memcpy(packet.target_id, rendezvous->self_public, crypto_box_PUBLICKEYBYTES);

#ifdef ASSOC_AVAILABLE
    /* ask DHT_assoc for IP_Ports for client_ids "close" to hash_unspecific_complete/2 */
    Assoc_close_nodes_simple state;
    memset(&state, 0, sizeof(state));
    state.close_count = 16;
    state.close_indices = calloc(16, sizeof(*state.close_indices));

    uint8_t found_cnt = Assoc_close_nodes_find(rendezvous->assoc, packet.hash_unspecific_half, &state);

    if (!found_cnt) {
#ifdef LOGGING
        loglog("rendezvous::publish(): no nodes to send data to. :-(\n");
#endif
        return;
    }

    uint8_t i, sent = 0;

    /* send to the four best verified and four random of the best 16
     * (requires some additions in assoc.*) */
    for (i = 0; i < found_cnt; i++)
        if ((i < 4) || !(rand() % 4)) {
            Client_data *entry = Assoc_client(rendezvous->assoc, state.close_indices[i]);

            if (entry) {
                IPPTsPng *assoc;

                if (entry->assoc4.timestamp > entry->assoc6.timestamp)
                    assoc = &entry->assoc4;
                else
                    assoc = &entry->assoc6;

                sendpacket(rendezvous->net, assoc->ip_port, &packet.type, sizeof(packet));
#ifdef LOGGING
                sprintf(logbuffer, "rendezvous::publish(): [%u] => [%u]\n", htons(rendezvous->net->port), htons(assoc->ip_port.port));
                loglog(logbuffer);
#endif
                sent++;
            }
        }

#ifdef LOGGING
    sprintf(logbuffer, "rendezvous::publish(): sent data to %u of %u clients.\n", sent, found_cnt);
    loglog(logbuffer);
#endif
#else
#ifdef LOGGING
    loglog("rendezvous::publish(): No ASSOC_AVAILABLE.\n");
#endif
#endif
}

static void send_replies(RendezVous *rendezvous, size_t i, size_t k)
{
    if (is_timeout(rendezvous->store[i].sent_at, RENDEZVOUS_SEND_AGAIN)) {
        rendezvous->store[i].sent_at = unix_time();
        sendpacket(rendezvous->net, rendezvous->store[i].ipp, &rendezvous->store[k].packet.type, sizeof(RendezVousPacket));
    }

    if (is_timeout(rendezvous->store[k].sent_at, RENDEZVOUS_SEND_AGAIN)) {
        rendezvous->store[k].sent_at = unix_time();
        sendpacket(rendezvous->net, rendezvous->store[k].ipp, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));
    }
}

static int packet_is_wanted(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored)
{
    if (rendezvous->timestamp == now_floored)
        if (!memcmp(packet->hash_unspecific_half, rendezvous->hash_unspecific_complete, HASHLEN / 2)) {
            /* validate that hash matches */
            uint8_t validate_in[HASHLEN / 2 + crypto_box_PUBLICKEYBYTES];
            memcpy(validate_in, rendezvous->hash_unspecific_complete + HASHLEN / 2, HASHLEN / 2);
            id_copy(validate_in + HASHLEN / 2, packet->target_id);

            uint8_t validate_out[HASHLEN];
            crypto_hash_sha512(validate_out, validate_in, sizeof(validate_in));

            if (!memcmp(packet->hash_specific_half, validate_out, HASHLEN / 2)) {
                rendezvous->functions.found_function(rendezvous->data, packet->target_id);
                return 1;
            }
        }

    return 0;
}

static int packet_is_update(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored, IP_Port *ipp)
{
    size_t i, k;

    for (i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
        if (rendezvous->store[i].match != 0) {
            /* one slot per target_id to catch resends */
            if (id_equal(rendezvous->store[i].packet.target_id, packet->target_id)) {
                /* if the entry is timed out, and it changed, reset flag for match and store */
                if (rendezvous->store[i].recv_at < now_floored) {
                    if (memcmp(&rendezvous->store[i].packet, packet, sizeof(*packet)) != 0) {
                        rendezvous->store[i].recv_at = now_floored;
                        rendezvous->store[i].ipp = *ipp;
                        rendezvous->store[i].packet = *packet;

                        rendezvous->store[i].match = 1;
                        rendezvous->store[i].sent_at = 0;
                    }
                } else if (rendezvous->store[i].match == 2) {
                    /* there exists a match, send the pairing their data
                     * (if RENDEZVOUS_SEND_AGAIN seconds have passed) */
                    for (k = 0; k < RENDEZVOUS_STORE_SIZE; k++)
                        if ((i != k) && (rendezvous->store[k].match == 2))
                            if (rendezvous->store[k].recv_at == now_floored)
                                if (!memcmp(rendezvous->store[i].packet.hash_unspecific_half,
                                            rendezvous->store[k].packet.hash_unspecific_half, HASHLEN / 2))
                                    send_replies(rendezvous, i, k);
                }

                return 1;
            }
        }

    return 0;
}

static int rendezvous_network_handler(void *object, IP_Port ip_port, uint8_t *data, uint32_t len)
{
    if (!object)
        return 0;

    /*
     * got to do two things here:
     * a) store up to 8 entries
     * b) on an incoming packet, see if the unencrypted half matches a previous one,
     *    if yes, send back the previous one
     * c) look if we got a match and callback
     */
    RendezVous *rendezvous = object;

    if (len != sizeof(RendezVousPacket))
        return 0;

    RendezVousPacket *packet = (RendezVousPacket *)data;

    if (rendezvous->self_public && id_equal(packet->target_id, rendezvous->self_public))
        return 0;

    uint64_t now = unix_time();
    uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);

    if (packet_is_wanted(rendezvous, packet, now_floored))
        return 1;

    if (packet_is_update(rendezvous, packet, now_floored, &ip_port))
        return 1;

    size_t i, matching = RENDEZVOUS_STORE_SIZE;

    /* if the data is a match to an existing, unmatched entry,
     * skip blocking */
    if (rendezvous->block_store_until >= now)
        for (i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
            if (rendezvous->store[i].match == 1)
                if (rendezvous->store[i].recv_at == now_floored)
                    if (!memcmp(rendezvous->store[i].packet.hash_unspecific_half,
                                packet->hash_unspecific_half, HASHLEN / 2)) {
                        /* "encourage" storing */
                        rendezvous->block_store_until = now - 1;
                        matching = i;
                        break;
                    }

    size_t pos = RENDEZVOUS_STORE_SIZE;

    if (!rendezvous->block_store_until) {
        pos = 0;
    } else if (rendezvous->block_store_until < now) {
        /* find free slot to store into */
        for (i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
            if ((rendezvous->store[i].match == 0) ||
                    is_timeout(rendezvous->store[i].recv_at, RENDEZVOUS_INTERVAL)) {
                pos = i;
                break;
            }

        if (pos == RENDEZVOUS_STORE_SIZE) {
            /* all full: randomize opening again */
            rendezvous->block_store_until = now_floored + RENDEZVOUS_INTERVAL + rand() % 30;

            if (matching < RENDEZVOUS_STORE_SIZE) {
                /* we got a match but can't store due to space:
                 * send replies, mark second slot */
                sendpacket(rendezvous->net, ip_port, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));
                sendpacket(rendezvous->net, rendezvous->store[i].ipp, data, sizeof(RendezVousPacket));

                rendezvous->store[i].match = 2;
                rendezvous->store[i].sent_at = now;
            }

            return 0;
        }
    } else {
        /* blocking */
        /* TODO: blacklist insisting publishers */
        return 0;
    }

    /* store */
    rendezvous->store[pos].recv_at = now_floored;
    rendezvous->store[pos].ipp = ip_port;
    rendezvous->store[pos].packet = *packet;

    rendezvous->store[pos].match = 1;
    rendezvous->store[pos].sent_at = 0;

    rendezvous->block_store_until = now + 60 + rand() % 1800;

    for (i = matching; i < RENDEZVOUS_STORE_SIZE; i++)
        if ((i != pos) && (rendezvous->store[i].match == 1))
            if (rendezvous->store[i].recv_at == now_floored)
                if (!memcmp(rendezvous->store[i].packet.hash_unspecific_half,
                            rendezvous->store[pos].packet.hash_unspecific_half, HASHLEN / 2)) {

                    send_replies(rendezvous, i, pos);

                    rendezvous->store[i].match = 2;
                    rendezvous->store[pos].match = 2;
                }

    return 0;
}

RendezVous *rendezvous_new(Assoc *assoc, Networking_Core *net)
{
    if (!assoc || !net)
        return NULL;

    RendezVous *rendezvous = calloc(1, sizeof(*rendezvous));

    if (!rendezvous)
        return NULL;

    rendezvous->assoc = assoc;
    rendezvous->net = net;

    networking_registerhandler(net, NET_PACKET_RENDEZVOUS, rendezvous_network_handler, rendezvous);
    return rendezvous;
}

void rendezvous_init(RendezVous *rendezvous, uint8_t *self_public)
{
    if (rendezvous && self_public)
        rendezvous->self_public = self_public;
}

int rendezvous_publish(RendezVous *rendezvous, char *text, uint64_t timestamp, RendezVous_callbacks *functions,
                       void *data)
{
    if (!rendezvous || !text || !functions)
        return 0;

    if (!rendezvous->self_public)
        return 0;

    if (!functions->found_function)
        return 0;

    if (((timestamp % RENDEZVOUS_INTERVAL) != 0) || (timestamp + RENDEZVOUS_INTERVAL < unix_time()))
        return 0;

    /*
     * user has input a text and a timestamp
     *
     * from text and timestamp, generate a 512bit hash (64bytes)
     * the first 32bytes are sent plain, the second 32bytes are
     * encrypted with our own key
     *
     * the first 32 are used to define the distance function
     */

    char texttime[32 + strlen(text)];
    size_t texttimelen = sprintf(texttime, "%s@%ld", text, timestamp);
    crypto_hash_sha512(rendezvous->hash_unspecific_complete, (const unsigned char *)texttime, texttimelen);

    uint8_t validate_in[HASHLEN / 2 + crypto_box_PUBLICKEYBYTES];
    memcpy(validate_in, rendezvous->hash_unspecific_complete + HASHLEN / 2, HASHLEN / 2);
    id_copy(validate_in + HASHLEN / 2, rendezvous->self_public);

    uint8_t validate_out[HASHLEN];
    crypto_hash_sha512(validate_out, validate_in, sizeof(validate_in));
    memcpy(rendezvous->hash_specific_half, validate_out, HASHLEN / 2);

    /* +30s: allow *some* slack in keeping the system time up to date */
    if (timestamp < unix_time())
        rendezvous->publish_starttime = timestamp;
    else
        rendezvous->publish_starttime = timestamp + 30;

    rendezvous->timestamp = timestamp;
    rendezvous->functions = *functions;
    rendezvous->data = data;
    rendezvous_do(rendezvous);

    return 1;
}

void rendezvous_do(RendezVous *rendezvous)
{
    /* nothing to publish */
    if (!rendezvous->publish_starttime)
        return;

    uint64_t now = unix_time();

    if (rendezvous->publish_starttime < now) {
        rendezvous->publish_starttime = 0;
        uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);

        /* timed out: stop publishing? */
        if (rendezvous->timestamp < now_floored) {
            rendezvous->timestamp = 0;

            if (rendezvous->functions.timeout_function)
                if (rendezvous->functions.timeout_function(rendezvous->data))
                    rendezvous->timestamp = now_floored;
        }

        if ((rendezvous->timestamp >= now_floored) && (rendezvous->timestamp < now_floored + RENDEZVOUS_INTERVAL)) {
            publish(rendezvous);

            /* on average, publish once a minute */
            rendezvous->publish_starttime = now + 45 + rand() % 30;
        }
    }
}

void rendezvous_kill(RendezVous *rendezvous)
{
    networking_registerhandler(rendezvous->net, NET_PACKET_RENDEZVOUS, NULL, NULL);
    free(rendezvous);
}
