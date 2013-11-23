
#include "rendezvous.h"
#include "network.h"
#include "net_crypto.h"
#include "assoc.h"
#include "util.h"

/* how often the same match may be re-announced */
#define RNDVZ_SEND_AGAIN (40U + rand() % 20U)

/* number of stored entries */
#define RNDVZ_STORE_OTHER 8
#define RNDVZ_STORE_WANTED 4

/* total len of hash over input/time */
#define HASHLEN crypto_hash_sha512_BYTES

/* hash pieces: sizes */
#define RNDVZ_PKT_UNSPCFC_LEN (HASHLEN / 4)
#define RNDVZ_PKT_REFID_LEN (HASHLEN / 4)
#define RNDVZ_PKT_SPCFC_LEN (HASHLEN / 2)

typedef struct RendezVousPacket {
    uint8_t  type;
    uint8_t  hash_unspecific_quarter[RNDVZ_PKT_UNSPCFC_LEN];
    uint8_t  hash_specific_half[RNDVZ_PKT_SPCFC_LEN];
    uint8_t  target_id[crypto_box_PUBLICKEYBYTES];
} RendezVousPacket;

typedef struct {
    uint64_t           recv_at;
    IP_Port            ipp;

    RendezVousPacket   packet;

    uint8_t            match;
    uint64_t           sent_at;
} RendezVous_Entry;

/* somewhat defined in messenger.c, but don't want to pull in all that sh*t */
#define ADDRESS_EXTRA_BYTES (sizeof(uint32_t) + sizeof(uint16_t))

typedef struct RendezVous {
    DHT               *dht;
    Assoc             *assoc;
    Networking_Core   *net;

    uint8_t           *self_public;
    uint64_t           block_store_until;

    uint64_t           timestamp;
    char              *text;
    uint8_t            nospam_chksum[ADDRESS_EXTRA_BYTES];
    uint64_t           publish_starttime;
    RendezVous_callbacks   functions;
    void                  *data;
    uint8_t            hash_unspecific_complete[HASHLEN];
    uint8_t            hash_specific_half[RNDVZ_PKT_SPCFC_LEN];
    uint8_t            getnodes_ref_id[crypto_box_PUBLICKEYBYTES]; /* the closest id we've found as contact point yet */

    uint8_t            found[RNDVZ_STORE_WANTED][crypto_box_PUBLICKEYBYTES + ADDRESS_EXTRA_BYTES];
    uint8_t            found_num;

    RendezVous_Entry   store[RNDVZ_STORE_OTHER];
} RendezVous;

/* Input:  unspecific of length HASHLEN
 *         id of length crypto_box_PUBLICKEYBYTES
 * Output: specific of length HASHLEN / 2
 */
static void hash_specific_half_calc(uint8_t *unspecific, uint8_t *id, uint8_t *specific)
{
    uint8_t validate_in[RNDVZ_PKT_SPCFC_LEN + crypto_box_PUBLICKEYBYTES];
    memcpy(validate_in, unspecific + (HASHLEN - RNDVZ_PKT_SPCFC_LEN), RNDVZ_PKT_SPCFC_LEN);
    id_copy(validate_in + RNDVZ_PKT_SPCFC_LEN, id);

    uint8_t validate_out[HASHLEN];
    crypto_hash_sha512(validate_out, validate_in, sizeof(validate_in));
    memcpy(specific, validate_out, RNDVZ_PKT_SPCFC_LEN);
}

/* Input:  specific of length HASHLEN / 2
 *         extra of length ADDRESS_EXTRA_BYTES
 * Output: modified specific
 */
static void hash_specific_extra_insert(uint8_t *specific, uint8_t *extra)
{
    size_t i;

    for (i = 0; i < ADDRESS_EXTRA_BYTES; i++)
        specific[i] ^= extra[i];
}

/* Input:  specific_calc of length HASHLEN / 2
 *         specific_recv of length HASHLEN / 2
 * Output: extra of length ADDRESS_EXTRA_BYTES
 */
static void hash_specific_extra_extract(uint8_t *specific_recv, uint8_t *specific_calc, uint8_t *extra)
{
    size_t i;

    for (i = 0; i < ADDRESS_EXTRA_BYTES; i++)
        extra[i] = specific_calc[i] ^ specific_recv[i];
}

/* can return NULL if none */
static IPPTsPng *entry_ippts(Client_data *entry)
{
    IPPTsPng *ippts;

    if (entry->assoc4.timestamp > entry->assoc6.timestamp) {
        ippts = &entry->assoc4;

        if (!ipport_isset(&ippts->ip_port)) {
            ippts = &entry->assoc6;

            if (!ipport_isset(&ippts->ip_port))
                return NULL;
        }
    } else {
        ippts = &entry->assoc6;

        if (!ipport_isset(&ippts->ip_port)) {
            ippts = &entry->assoc4;

            if (!ipport_isset(&ippts->ip_port))
                return NULL;
        }
    }

    return ippts;
}

static void publish(RendezVous *rendezvous)
{
    RendezVousPacket packet;
    packet.type = NET_PACKET_RENDEZVOUS;
    memcpy(packet.hash_unspecific_quarter, rendezvous->hash_unspecific_complete, RNDVZ_PKT_UNSPCFC_LEN);
    memcpy(packet.hash_specific_half, rendezvous->hash_specific_half, RNDVZ_PKT_SPCFC_LEN);
    memcpy(packet.target_id, rendezvous->self_public, crypto_box_PUBLICKEYBYTES);

    size_t wanted_good = 4;
    size_t wanted_bad = 4;

    /* ask DHT_assoc for IP_Ports for client_ids "close" to hash_unspecific_complete/2 */
    size_t wanted_total = 16;

    Assoc_close_entries state;
    memset(&state, 0, sizeof(state));
    id_copy(state.wanted_id, rendezvous->getnodes_ref_id);
    state.count = wanted_total;
    state.count_good = wanted_good;
    state.result = calloc(wanted_total, sizeof(*state.result));

    uint8_t found_cnt = Assoc_get_close_entries(rendezvous->assoc, &state);

    if (!found_cnt) {
#ifdef LOGGING
        loglog("rendezvous::publish(): no nodes to send data to. :-(\n");
#endif
        return;
    }

    /* send to the four best verified and four random of the next 12
     *
     * it's not 100% guaranteed to be at least four bad ones, because
     * enforcing that isn't worth so much effort...  */
    size_t modulus = found_cnt - state.count_good;
    size_t remainder = wanted_bad + (wanted_good - state.count_good);

    if (!modulus) /* shouldn't matter, because then the 2nd part of if() never comes into play */
        modulus = 1; /* still, avoid any chance of a crash */

    uint8_t i, sent = 0;

    for (i = 0; i < found_cnt; i++)
        if ((i < state.count_good) || ((rand() % modulus) <= remainder)) {
            Client_data *entry = state.result[i];

            if (entry) {
                IPPTsPng *ippts = entry_ippts(entry);

                if (!ippts)
                    continue;

                sendpacket(rendezvous->net, ippts->ip_port, &packet.type, sizeof(packet));
#ifdef LOGGING
                sprintf(logbuffer, "rendezvous::publish(): [%u] => [%u]\n", htons(rendezvous->net->port), htons(ippts->ip_port.port));
                loglog(logbuffer);
#endif
                sent++;

                if (sent >= wanted_good + wanted_bad)
                    break;
            }
        }


    /* improve target vector if possible */
    uint8_t *getnodes_ref_id;

    if (found_cnt > state.count_good) {
        Client_data *entry_good = state.result[0];
        Client_data *entry_bad = state.result[state.count_good];

        if (1 == id_closest(state.wanted_id, entry_good->client_id, entry_bad->client_id))
            getnodes_ref_id = entry_good->client_id;
        else
            getnodes_ref_id = entry_bad->client_id;
    } else {
        Client_data *entry = state.result[0];

        getnodes_ref_id = entry->client_id;
    }

    if (1 == id_closest(state.wanted_id, getnodes_ref_id, rendezvous->getnodes_ref_id)) {
        id_copy(rendezvous->getnodes_ref_id, getnodes_ref_id);
    }


    /* also do a getnodes on the best (up to) two good nodes... */
    for (i = state.count_good > 2 ? 2 : state.count_good; i > 0; i--) {
        Client_data *entry = state.result[i - 1];
        IPPTsPng *ippts = entry_ippts(entry);

        if (!ippts)
            continue;

        DHT_getnodes(rendezvous->dht, &ippts->ip_port, entry->client_id, rendezvous->getnodes_ref_id);
    }

    /* ... and on the best two bad nodes (because they're probably "closer" than the good ones) */
    if (found_cnt > state.count_good) {
        uint8_t getnodes_bad_sent = 0;

        for (i = state.count_good; (i < found_cnt) && (getnodes_bad_sent < 2); i++) {
            Client_data *entry = state.result[i];
            IPPTsPng *ippts = entry_ippts(entry);

            if (ippts) {
                DHT_getnodes(rendezvous->dht, &ippts->ip_port, entry->client_id, rendezvous->getnodes_ref_id);
                getnodes_bad_sent++;
            }
        }
    }

#ifdef LOGGING
    sprintf(logbuffer, "rendezvous::publish(): sent data to %u of %u clients.\n", sent, found_cnt);
    loglog(logbuffer);
#endif
}

static void send_replies(RendezVous *rendezvous, size_t i, size_t k)
{
    if (is_timeout(rendezvous->store[i].sent_at, RNDVZ_SEND_AGAIN)) {
        rendezvous->store[i].sent_at = unix_time();
        sendpacket(rendezvous->net, rendezvous->store[i].ipp, &rendezvous->store[k].packet.type, sizeof(RendezVousPacket));
    }

    if (is_timeout(rendezvous->store[k].sent_at, RNDVZ_SEND_AGAIN)) {
        rendezvous->store[k].sent_at = unix_time();
        sendpacket(rendezvous->net, rendezvous->store[k].ipp, &rendezvous->store[i].packet.type, sizeof(RendezVousPacket));
    }
}

static int packet_is_wanted(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored)
{
    /* only if we're currently searching */
    if (rendezvous->timestamp == now_floored)
        if (!memcmp(packet->hash_unspecific_quarter, rendezvous->hash_unspecific_complete, RNDVZ_PKT_UNSPCFC_LEN)) {
            uint8_t i;

            for (i = 0; i < RNDVZ_STORE_WANTED; i++)
                if (id_equal(rendezvous->found[i], packet->target_id))
                    return 1;

            uint8_t hash_specific_half[RNDVZ_PKT_SPCFC_LEN];
            hash_specific_half_calc(rendezvous->hash_unspecific_complete, packet->target_id, hash_specific_half);

            if (!memcmp(packet->hash_specific_half + ADDRESS_EXTRA_BYTES, hash_specific_half + ADDRESS_EXTRA_BYTES,
                        RNDVZ_PKT_SPCFC_LEN - ADDRESS_EXTRA_BYTES)) {
                uint8_t found_pos = rendezvous->found_num % RNDVZ_STORE_WANTED;

                rendezvous->found_num++;
                id_copy(rendezvous->found[found_pos], packet->target_id);
                hash_specific_extra_extract(packet->hash_specific_half, hash_specific_half,
                                            rendezvous->found[found_pos] + crypto_box_PUBLICKEYBYTES);
                rendezvous->functions.found_function(rendezvous->data, rendezvous->found[found_pos]);
                return 1;
            }
        }

    return 0;
}

static int packet_is_update(RendezVous *rendezvous, RendezVousPacket *packet, uint64_t now_floored, IP_Port *ipp)
{
    size_t i, k;

    for (i = 0; i < RNDVZ_STORE_OTHER; i++)
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
                     * (if RNDVZ_SEND_AGAIN seconds have passed) */
                    for (k = 0; k < RNDVZ_STORE_OTHER; k++)
                        if ((i != k) && (rendezvous->store[k].match == 2))
                            if (rendezvous->store[k].recv_at == now_floored)
                                if (!memcmp(rendezvous->store[i].packet.hash_unspecific_quarter,
                                            rendezvous->store[k].packet.hash_unspecific_quarter, RNDVZ_PKT_UNSPCFC_LEN))
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

    size_t i, matching = RNDVZ_STORE_OTHER;

    /* if the data is a match to an existing, unmatched entry,
     * skip blocking */
    if (rendezvous->block_store_until >= now)
        for (i = 0; i < RNDVZ_STORE_OTHER; i++)
            if (rendezvous->store[i].match == 1)
                if (rendezvous->store[i].recv_at == now_floored)
                    if (!memcmp(rendezvous->store[i].packet.hash_unspecific_quarter,
                                packet->hash_unspecific_quarter, RNDVZ_PKT_UNSPCFC_LEN)) {
                        /* "encourage" storing */
                        rendezvous->block_store_until = now - 1;
                        matching = i;
                        break;
                    }

    size_t pos = RNDVZ_STORE_OTHER;

    if (!rendezvous->block_store_until) {
        pos = 0;
    } else if (rendezvous->block_store_until < now) {
        /* find free slot to store into */
        for (i = 0; i < RNDVZ_STORE_OTHER; i++)
            if ((rendezvous->store[i].match == 0) ||
                    is_timeout(rendezvous->store[i].recv_at, RENDEZVOUS_INTERVAL)) {
                pos = i;
                break;
            }

        if (pos == RNDVZ_STORE_OTHER) {
            /* all full: randomize opening again */
            rendezvous->block_store_until = now_floored + RENDEZVOUS_INTERVAL + rand() % 30;

            if (matching < RNDVZ_STORE_OTHER) {
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

    rendezvous->block_store_until = now + RENDEZVOUS_STORE_BLOCK;

    for (i = matching; i < RNDVZ_STORE_OTHER; i++)
        if ((i != pos) && (rendezvous->store[i].match == 1))
            if (rendezvous->store[i].recv_at == now_floored)
                if (!memcmp(rendezvous->store[i].packet.hash_unspecific_quarter,
                            rendezvous->store[pos].packet.hash_unspecific_quarter, RNDVZ_PKT_UNSPCFC_LEN)) {

                    send_replies(rendezvous, i, pos);

                    rendezvous->store[i].match = 2;
                    rendezvous->store[pos].match = 2;
                }

    return 0;
}

RendezVous *new_rendezvous(DHT *dht, Assoc *assoc, Networking_Core *net)
{
    if (!dht || !assoc || !net)
        return NULL;

    RendezVous *rendezvous = calloc(1, sizeof(*rendezvous));

    if (!rendezvous)
        return NULL;

    rendezvous->dht = dht;
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

static void prepare_publish(RendezVous *rendezvous)
{
    if (!rendezvous || !rendezvous->text)
        return;

    char texttime[32 + strlen(rendezvous->text)];
    size_t texttimelen = sprintf(texttime, "%ld@%s", rendezvous->timestamp, rendezvous->text);
    crypto_hash_sha512(rendezvous->hash_unspecific_complete, (const unsigned char *)texttime, texttimelen);

    hash_specific_half_calc(rendezvous->hash_unspecific_complete, rendezvous->self_public, rendezvous->hash_specific_half);
    hash_specific_extra_insert(rendezvous->hash_specific_half, rendezvous->nospam_chksum);

    memcpy(rendezvous->getnodes_ref_id, rendezvous->hash_unspecific_complete + RNDVZ_PKT_UNSPCFC_LEN, RNDVZ_PKT_REFID_LEN);
    memset(rendezvous->getnodes_ref_id + RNDVZ_PKT_REFID_LEN, 0, sizeof(rendezvous->getnodes_ref_id) - RNDVZ_PKT_REFID_LEN);

    Client_data *good = NULL, *bad = NULL;
    Assoc_get_two_closest_entries(rendezvous->assoc, rendezvous->getnodes_ref_id, &good, &bad);

    if (good) {
        if (bad && (2 == id_closest(rendezvous->getnodes_ref_id, good->client_id, bad->client_id)))
            id_copy(rendezvous->getnodes_ref_id, bad->client_id);
        else
            id_copy(rendezvous->getnodes_ref_id, good->client_id);

        IPPTsPng *ippts = entry_ippts(good);

        if (ippts)
            DHT_getnodes(rendezvous->dht, &ippts->ip_port, good->client_id, rendezvous->getnodes_ref_id);
    } else if (bad) {
        id_copy(rendezvous->getnodes_ref_id, bad->client_id);
    } else {
        size_t i;

        /* umm... no other node available? fill most of it with random data,
         * leaving only the very first byte as initial correct search vector */
        for (i = 1; i < sizeof(rendezvous->getnodes_ref_id); i++)
            rendezvous->getnodes_ref_id[i] = rand();
    }
}

int rendezvous_publish(RendezVous *rendezvous, uint8_t *nospam_chksum, char *text, uint64_t timestamp,
                       RendezVous_callbacks *functions, void *data)
{
    if (!rendezvous || !text || !functions)
        return 0;

    if (!rendezvous->self_public)
        return 0;

    if (!functions->found_function)
        return 0;

    if (strlen(text) < RENDEZVOUS_PASSPHRASE_MINLEN)
        return 0;

    if (((timestamp % RENDEZVOUS_INTERVAL) != 0) || (timestamp + RENDEZVOUS_INTERVAL < unix_time()))
        return 0;

    rendezvous->timestamp = timestamp;
    rendezvous->functions = *functions;
    rendezvous->data = data;
    rendezvous->found_num = 0;

    memcpy(rendezvous->nospam_chksum, nospam_chksum, sizeof(rendezvous->nospam_chksum));
    size_t textlen = strlen(text);
    rendezvous->text = realloc(rendezvous->text, textlen + 1);

    if (!rendezvous->text)
        return 0;

    memcpy(rendezvous->text, text, textlen + 1);

    prepare_publish(rendezvous);

    if (timestamp < unix_time()) /* interval already going: start immediately */
        rendezvous->publish_starttime = timestamp;
    else  /* add delay, allow *some* slack in keeping the system time up to date */
        rendezvous->publish_starttime = timestamp + RENDEZVOUS_PUBLISH_INITIALDELAY;

    do_rendezvous(rendezvous);

    return 1;
}

void do_rendezvous(RendezVous *rendezvous)
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
                if (rendezvous->functions.timeout_function(rendezvous->data)) {
                    rendezvous->timestamp = now_floored;
                    prepare_publish(rendezvous);
                }

#ifdef LOGGING

            if (!rendezvous->timestamp)
                loglog("rendezvous: timed out.\n");

#endif
        }

        if ((rendezvous->timestamp >= now_floored) && (rendezvous->timestamp < now_floored + RENDEZVOUS_INTERVAL)) {
            publish(rendezvous);

            /* on average, publish about once per 45 seconds */
            rendezvous->publish_starttime = now + RENDEZVOUS_PUBLISH_SENDAGAIN;
        }
    }
}

void kill_rendezvous(RendezVous *rendezvous)
{
    if (rendezvous) {
        networking_registerhandler(rendezvous->net, NET_PACKET_RENDEZVOUS, NULL, NULL);
        free(rendezvous);
    }
}
