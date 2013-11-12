
#ifndef __RENDEZVOUS_H__
#define __RENDEZVOUS_H__

/* for the legalese, see tox.h */

#include "network.h"
#include "assoc.h"
#include "util.h"

/*
 * module to facilitate ID exchange by using the network,
 * a common secret and a timestamp
 *
 *
 * Preparations:
 *
 * from the secret and timestamp, a 512bit hash is produced
 * the first half is used as a virtual ref_id for distance
 *     purposes
 * the second half is again hashed with the own public_id
 * the first sizeof(uint32_t) + sizeof(uint16_t) are XORed
 * against the own friend address extension
 *
 * the combined halves are sent as a packet into the net
 *     towards the virtual ref_id (the first half)
 *
 *
 * Receiving a packet "for us":
 *
 * If the packet is "for us" (we're in search mode at the
 * time and its first half matches our first half), the
 * second half is verified. If it checks out, the callback
 * is called.
 *
 *
 * Receiving a packet not for us:
 *
 * Other packets can be stored, up to NET_PACKET_RENDEZVOUS
 * of them. But only rarely: A new, unmatching packet is only
 * accepted at least RENDEZVOUS_STORE_BLOCK seconds (see below)
 * after a previous one.
 *
 * If we find a match while we decide about storing, and the
 * matching entry hadn't had a previous match, the new packet
 * bypasses the timeouts.
 * On a match, the two senders are both informed about the match
 * (unless they were already informed recently).
 *
 * (UNDECIDED: Should we allow to store for (short-term) future
 * matching, e.g. up to 30m? Requires a timestamp in the packet.)
 */

/* minimum length of text to generate hash from */
#define RENDEZVOUS_PASSPHRASE_MINLEN 16U

/* publish not right on time: allow some slack for people's clocks */
#define RENDEZVOUS_PUBLISH_INITIALDELAY 30U

/* publish again after initial publish every (this) seconds */
#define RENDEZVOUS_PUBLISH_SENDAGAIN (35 + rand() % 20)

/* non-matching packet is accepted for storing after (this) seconds */
#define RENDEZVOUS_STORE_BLOCK (60U + rand() % 1800U)

typedef struct Assoc Assoc;
typedef struct RendezVous RendezVous;

typedef void (*RendezVous_callback_found)(void *data, uint8_t *client_id);
/* return 1 to keep publishing, 0 to stop */
typedef uint8_t (*RendezVous_callback_timeout)(void *data);

typedef struct {
    RendezVous_callback_found    found_function;
    RendezVous_callback_timeout  timeout_function;
} RendezVous_callbacks;

#ifdef ASSOC_AVAILABLE
RendezVous *rendezvous_new(Assoc *assoc, Networking_Core *net);
#else
typedef struct DHT DHT;

RendezVous *new_rendezvous(DHT *dht, Networking_Core *net);
#endif

void rendezvous_init(RendezVous *rendezvous, uint8_t *self_public);

/* timestamp must be cut to this accuracy (3 minutes) */
#define RENDEZVOUS_INTERVAL 180U

int rendezvous_publish(RendezVous *rendezvous, uint8_t *nospam_chksm, char *text, uint64_t timestamp,
                       RendezVous_callbacks *functions, void *data);

void do_rendezvous(RendezVous *rendezvous);

void kill_rendezvous(RendezVous *rendezvous);

#endif /* __RENDEZVOUS_H__ */
