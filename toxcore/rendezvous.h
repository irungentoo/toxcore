
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

RendezVous *rendezvous_new(DHT_assoc *dhtassoc, Networking_Core *net, uint8_t *self_public);

int rendezvous_publish(RendezVous *rendezvous, char *text, uint64_t timestamp, RendezVous_callbacks *functions, void *data);

void rendezvous_do(RendezVous *rendezvous);

void rendezvous_kill(RendezVous *rendezvous);

#endif /* __RENDEZVOUS_H__ */
