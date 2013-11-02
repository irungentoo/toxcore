
#ifndef __RENDEZVOUS_H__
#define __RENDEZVOUS_H__

/* for the legalese, see tox.h */

#include "network.h"
#include "util.h"

/*
 * module to facilitate ID exchange by using the network,
 * a common secret and a timestamp
 */
typedef struct DHT_assoc DHT_assoc;
typedef struct RendezVous RendezVous;

typedef void (*RendezVous_callback_found)(void *data, uint8_t *client_id);
/* return 1 to keep publishing, 0 to stop */
typedef int (*RendezVous_callback_timeout)(void *data);

typedef struct {
    RendezVous_callback_found    found_function;
    RendezVous_callback_timeout  timeout_function;
} RendezVous_callbacks;

RendezVous *rendezvous_new(DHT_assoc *dhtassoc, Networking_Core *net);

void rendezvous_init(RendezVous *rendezvous, uint8_t *self_public, uint8_t *self_secret);

/* timestamp must be cut to this accuracy (5 minutes) */
#define RENDEZVOUS_INTERVAL 300U

int rendezvous_publish(RendezVous *rendezvous, char *text, uint64_t timestamp, RendezVous_callbacks *functions, void *data);

void rendezvous_do(RendezVous *rendezvous);

void rendezvous_kill(RendezVous *rendezvous);

/* for testing purposes ONLY */
typedef int (*Rendezvous_sendpacket)(Networking_Core *net, IP_Port ipport, uint8_t *data, uint32_t len);
void rendezvous_testing(RendezVous *rendezvous, Networking_Core *net, Rendezvous_sendpacket sendpacket)
#ifndef AUTO_TESTS
__attribute__((__deprecated__))
#endif
;

#endif /* __RENDEZVOUS_H__ */
