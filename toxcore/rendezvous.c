
#include "rendezvous.h"
#include "network.h"
#include "net_crypto.h"

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
    uint8_t  hash_complete_half[HASHLEN / 2];
    uint8_t  hash_encrypted[HASHLEN / 2];
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
    Networking_Core   *net;
    Rendezvous_sendpacket sendpacket;

    uint8_t           *self_public;
    uint8_t           *self_secret;
    uint64_t           publish_starttime;
    uint64_t           block_store_until;

    RendezVous_callbacks   functions;
    void                  *data;
    uint64_t           timestamp;
    uint8_t            hash_complete[HASHLEN];
    uint8_t            hash_encrypted[HASHLEN / 2];

    RendezVous_Entry   store[RENDEZVOUS_STORE_SIZE];
} RendezVous;

static size_t encrypt(uint8_t *encrypted, const uint8_t *plaintext, size_t len, uint8_t *secret_key)
{
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));

    return crypto_secretbox(encrypted, plaintext, len, nonce, secret_key);
}

static size_t decrypt(const uint8_t *encrypted, uint8_t *plaintext, size_t len, uint8_t *public_key)
{
    uint8_t nonce[crypto_secretbox_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));

    return crypto_secretbox_open(plaintext, encrypted, len, nonce, public_key);
}

static void publish(RendezVous *rendezvous)
{
    RendezVousPacket packet;
    // uint8_t packet[1 + HASHLEN + crypto_box_PUBLICKEYBYTES];
    packet.type = NET_PACKET_RENDEZVOUS;
    memcpy(packet.hash_complete_half, rendezvous->hash_complete, HASHLEN / 2);
    memcpy(packet.hash_encrypted, rendezvous->hash_encrypted, HASHLEN / 2);
    memcpy(packet.target_id, rendezvous->self_public, crypto_box_PUBLICKEYBYTES);

    /* TODO: ask DHT_assoc for IP_Ports for client_ids "close" to hash_complete/2 */
    IP_Port ipport;
    ipport.ip.family = AF_INET;
    ipport.ip.ip4.uint32 = htonl((127 << 24) + 1);
    ipport.port = 33445;

    /* TODO:
     * send to the four best verified and four random of the best 16
     * (requires some additions in assoc.*) */
    rendezvous->sendpacket(rendezvous->net, ipport, &packet.type, sizeof(packet));
}

static void send_replies(RendezVous *rendezvous, size_t i, size_t k)
{
    if (is_timeout(rendezvous->store[i].sent_at, RENDEZVOUS_SEND_AGAIN)) {
        rendezvous->store[i].sent_at = unix_time();
        rendezvous->sendpacket(rendezvous->net, rendezvous->store[i].ipp, &rendezvous->store[k].packet.type, sizeof(RendezVousPacket));
    }

    if (is_timeout(rendezvous->store[k].sent_at, RENDEZVOUS_SEND_AGAIN)) {
        rendezvous->store[k].sent_at = unix_time();
        rendezvous->sendpacket(rendezvous->net, rendezvous->store[k].ipp, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));
    }
}

static int packet_is_wanted(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored)
{
    if (rendezvous->timestamp == now_floored)
        if (!memcmp(packet->hash_complete_half, rendezvous->hash_complete, HASHLEN / 2)) {
            /* validate that encryption matches */
            uint8_t validate[HASHLEN];
            size_t declen = decrypt(packet->hash_encrypted, validate, HASHLEN / 2, packet->target_id);
            if (!memcmp(rendezvous->hash_complete + HASHLEN / 2, validate, declen))
                rendezvous->functions.found_function(rendezvous->data, packet->target_id);

            return 1;
        }

    return 0;
}

static int packet_is_update(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored, IP_Port *ipp)
{
    size_t i, k;

    for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
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
                    for(k = 0; k < RENDEZVOUS_STORE_SIZE; k++)
                        if ((i != k) && (rendezvous->store[k].match == 2))
                            if (rendezvous->store[k].recv_at == now_floored)
                                if (!memcmp(rendezvous->store[i].packet.hash_complete_half,
                                            rendezvous->store[k].packet.hash_complete_half, HASHLEN / 2))
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
        for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
            if (rendezvous->store[i].match == 1)
                if (rendezvous->store[i].recv_at == now_floored)
                    if (!memcmp(rendezvous->store[i].packet.hash_complete_half,
                            packet->hash_complete_half, HASHLEN / 2)) {
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
        for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
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
                rendezvous->sendpacket(rendezvous->net, ip_port, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));
                rendezvous->sendpacket(rendezvous->net, rendezvous->store[i].ipp, data, sizeof(RendezVousPacket));

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

    for(i = matching; i < RENDEZVOUS_STORE_SIZE; i++)
        if ((i != pos) && (rendezvous->store[i].match == 1))
            if (rendezvous->store[i].recv_at == now_floored)
                if (!memcmp(rendezvous->store[i].packet.hash_complete_half,
                            rendezvous->store[pos].packet.hash_complete_half, HASHLEN / 2)) {

                    send_replies(rendezvous, i, pos);

                    rendezvous->store[i].match = 2;
                    rendezvous->store[pos].match = 2;
                }

    return 0;
}

RendezVous *rendezvous_new(DHT_assoc *dhtassoc, Networking_Core *net)
{
    if (!dhtassoc || !net)
        return NULL;

    RendezVous *rendezvous = calloc(1, sizeof(*rendezvous));
    if (!rendezvous)
        return NULL;

    rendezvous->net = net;
    rendezvous->sendpacket = sendpacket;
    networking_registerhandler(net, NET_PACKET_RENDEZVOUS, rendezvous_network_handler, rendezvous);
    return rendezvous;
}

void rendezvous_init(RendezVous *rendezvous, uint8_t *self_public, uint8_t *self_secret)
{
    if (rendezvous && self_public && self_secret) {
        rendezvous->self_public = self_public;
        rendezvous->self_secret = self_secret;
    }
}

int rendezvous_publish(RendezVous *rendezvous, char *text, uint64_t timestamp, RendezVous_callbacks *functions, void *data)
{
    if (!rendezvous || !text || !functions)
        return 0;

    if (!rendezvous->self_public || !rendezvous->self_secret)
        return 0;

    if (!functions->found_function)
        return 0;

    if (((timestamp % RENDEZVOUS_INTERVAL) != 0) || (timestamp < unix_time()))
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
    crypto_hash_sha512(rendezvous->hash_complete, (const unsigned char *)texttime, texttimelen);
    size_t enclen = encrypt(rendezvous->hash_encrypted, rendezvous->hash_complete + HASHLEN / 2, HASHLEN / 2, rendezvous->self_secret);
    if (enclen < HASHLEN / 2)
        memset(&rendezvous->hash_encrypted[enclen], 0, HASHLEN / 2 - enclen);

    /* +30s: allow *some* slack in keeping the system time up to date */
    rendezvous->publish_starttime = timestamp + 30;
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
            if (!rendezvous->functions.timeout_function)
                return;

            if (!rendezvous->functions.timeout_function(rendezvous->data))
                return;

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

void rendezvous_testing(RendezVous *rendezvous, Networking_Core *net, Rendezvous_sendpacket sendpacket)
{
    if (rendezvous) {
        rendezvous->net = net;
        rendezvous->sendpacket = sendpacket;
    }
}
