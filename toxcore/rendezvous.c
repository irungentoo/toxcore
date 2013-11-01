
#include "rendezvous.h"
#include "network.h"

/* network: packet id */
#define NET_PACKET_RENDEZVOUS 8

/* 5 minutes */
#define RENDEZVOUS_INTERVAL 300U

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
    uint64_t           timestamp;
    IP_Port            ipp;

    RendezVousPacket   packet;

    uint8_t            matched;
} RendezVous_Entry;

typedef struct RendezVous {
    Networking_Core   *net;
    uint8_t           *self_public;
    uint64_t           waituntil;
    uint64_t           acceptstore;

    RendezVous_callback    function;
    void                  *data;
    uint64_t           timestamp;
    uint8_t            hash_complete[HASHLEN];
    uint8_t            hash_encrypted[HASHLEN / 2];

    RendezVous_Entry   store[RENDEZVOUS_STORE_SIZE];
} RendezVous;

static size_t encrypt(uint8_t *encrypted, const uint8_t *plaintext, size_t len, uint8_t *public_key)
{
    return crypto_box(encrypted, plaintext, len, 0, public_key, NULL);
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

    /* NOT TO ALL */
    sendpacket(rendezvous->net, ipport, &packet.type, sizeof(packet));
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
    if (id_equal(packet->target_id, rendezvous->self_public))
        return 0;

    uint64_t now = unix_time();
    uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);
    if (!memcmp(packet->hash_complete_half, rendezvous->hash_complete, HASHLEN / 2)) {
        if (rendezvous->timestamp == now_floored) {
            /* TODO:
             * validate that encryption matches
             */
            rendezvous->function(rendezvous->data, packet->target_id);
        }

        return 1;
    }

    size_t i, pos = RENDEZVOUS_STORE_SIZE;
    if (!rendezvous->acceptstore) {
        pos = 0;
    } else if (rendezvous->acceptstore < now) {
        /* duplicate? */
        for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
            if (id_equal(rendezvous->store[i].packet.target_id, packet->target_id)) {
                /* should we check if the rest of the packet matches? */
                return 0;
            }

        /* find free slot to store into */
        for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
            if (is_timeout(rendezvous->store[i].timestamp, RENDEZVOUS_INTERVAL)) {
                pos = i;
                break;
            }

        /* if all full, randomize opening again */
        if (pos == RENDEZVOUS_STORE_SIZE) {
            rendezvous->acceptstore = now + rand() % RENDEZVOUS_INTERVAL;
            return 0;
        }
    } else {
        /* TODO: blacklist insistant publishers */
        return 0;
    }

    /* store */
    rendezvous->store[pos].packet = *packet;
    rendezvous->store[pos].timestamp = now;
    rendezvous->store[pos].ipp = ip_port;
    rendezvous->acceptstore = now + 60 + rand() % 1800;

    for(i = 0; i < RENDEZVOUS_STORE_SIZE; i++)
        if ((i != pos) && !is_timeout(rendezvous->store[i].timestamp, RENDEZVOUS_INTERVAL))
            if (!rendezvous->store[i].matched) {
                if (!memcmp(rendezvous->store[i].packet.hash_complete_half,
                            rendezvous->store[pos].packet.hash_complete_half, HASHLEN / 2)) {

                    sendpacket(rendezvous->net, rendezvous->store[i].ipp, &rendezvous->store[pos].packet.type, sizeof(RendezVousPacket));
                    sendpacket(rendezvous->net, rendezvous->store[pos].ipp, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));

                    rendezvous->store[i].matched = 1;
                    rendezvous->store[pos].matched = 1;
                }
            }

    return 0;
}

RendezVous *rendezvous_new(DHT_assoc *dhtassoc, Networking_Core *net, uint8_t *self_public)
{
    if (!dhtassoc || !net || !self_public)
        return NULL;

    RendezVous *rendezvous = calloc(1, sizeof(*rendezvous));
    if (!rendezvous)
        return NULL;

    rendezvous->net = net;
    rendezvous->self_public = self_public;

    networking_registerhandler(net, NET_PACKET_RENDEZVOUS, rendezvous_network_handler, rendezvous);
    return rendezvous;
}

int rendezvous_publish(RendezVous *rendezvous, char *text, uint64_t timestamp, RendezVous_callback function, void *data)
{
    if (!rendezvous || !text || !function)
        return 0;

    if ((timestamp % RENDEZVOUS_INTERVAL) != 0)
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
    // size_t enclen = crypto_box(rendezvous->hash_encrypted, rendezvous->hash_complete + HASHLEN / 2, HASHLEN / 2, 0, rendezvous->self_public, NULL);
    size_t enclen = encrypt(rendezvous->hash_encrypted, rendezvous->hash_complete + HASHLEN / 2, HASHLEN / 2, rendezvous->self_public);
    if (enclen < HASHLEN / 2)
        memset(&rendezvous->hash_encrypted[enclen], 0, HASHLEN / 2 - enclen);

    rendezvous->waituntil = timestamp;
    rendezvous->function = function;
    rendezvous->data = data;
    rendezvous_do(rendezvous);

    return 1;
}

void rendezvous_do(RendezVous *rendezvous)
{
    uint64_t now = unix_time();
    if (now > rendezvous->waituntil) {
        uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);
        if ((rendezvous->timestamp >= now_floored) && (rendezvous->timestamp < now_floored + RENDEZVOUS_INTERVAL))
            publish(rendezvous);

        rendezvous->waituntil = now + 60;
    }
}

void rendezvous_kill(RendezVous *rendezvous)
{
    networking_registerhandler(rendezvous->net, NET_PACKET_RENDEZVOUS, NULL, NULL);
    free(rendezvous);
}
