
#ifndef __ASSOC_H__
#define __ASSOC_H__

/* used by rendezvous */
#define ASSOC_AVAILABLE

/* For the legalese parts, see tox.h. */

/*
 * Module to store currently unused ID <=> IP associations
 * for a potential future use
 */

typedef struct IP_Port IP_Port;
typedef struct Assoc Assoc;

/*****************************************************************************/

/* custom distance handler, if it's not ID-distance based
 * return values exactly like id_closest() */
typedef int (*Assoc_distance_relative_callback)(Assoc *assoc, void *callback_data, uint8_t *client_id,
        uint8_t *client_id1, uint8_t *client_id2);

#define DISTANCE_INDEX_DISTANCE_BITS 44

/* absolute distance: can be same for different client_id_check values
 * return value should have DISTANCE_INDEX_DISTANCE_BITS valid bits */
typedef uint64_t (*Assoc_distance_absolute_callback)(Assoc *assoc, void *callback_data,
        uint8_t *client_id_ref, uint8_t *client_id_check);

/*****************************************************************************/

/* Central entry point for new associations: add a new candidate to the cache */
void Assoc_add_entry(Assoc *assoc, uint8_t *id, IPPTs *ippts_send, IP_Port *ipp_recv);

/*****************************************************************************/

typedef struct Assoc_close_entries {
    uint8_t                           *wanted_id;          /* the target client_id */
    void                              *custom_data;        /* given to distance functions */

    Assoc_distance_relative_callback   distance_relative_func;
    Assoc_distance_absolute_callback   distance_absolute_func;

    uint8_t                            count_good;   /* that many should be "good" w.r.t. timeout */
    uint8_t                            count;        /* allocated number of close_indices */
    Client_data                      **result;
} Assoc_close_entries;

/* find up to close_count nodes to put into close_nodes_used of ID_Nodes
 * the distance functions can be NULL, then standard distance functions will be used
 * the caller is responsible for allocating close_indices of sufficient size
 *
 * returns 0 on error
 * returns the number of found nodes and the list of indices usable by Assoc_client()
 *    the caller is assumed to be registered from Assoc_register_callback()
 *    if they aren't, they should copy the Client_data and call Assoc_client_drop()
 */
uint8_t Assoc_get_close_entries(Assoc *assoc, Assoc_close_entries *close_entries);

/*****************************************************************************/

/* create */
Assoc *new_Assoc(DHT *dht);

/* avoid storing own ID/assoc */
void Assoc_self_client_id_changed(Assoc *assoc);

/* destroy */
void kill_Assoc(Assoc *assoc);

#endif /* !__ASSOC_H__ */
