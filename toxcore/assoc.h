
#ifndef __ASSOC_H__
#define __ASSOC_H__

/* used by rendezvous */
#define ASSOC_AVAILABLE

/* For the legalese parts, see tox.h. */

/* enumerated lists are superior to magic numbers */
enum NODE_STATUS { BAD, SEENB_HEARDG, SEENG, USED };

/*
 * Module to store currently unused ID <=> IP associations
 * for a potential future use
 */

typedef struct Assoc Assoc;

/*****************************************************************************/

/* custom distance handler, if it's not ID-distance based
 * return values exactly like id_closest() */
typedef int (*Assoc_distance_relative_callback)(const Assoc *assoc, void *callback_data, const uint8_t *client_id,
        const uint8_t *client_id1, const uint8_t *client_id2);

#define DISTANCE_INDEX_DISTANCE_BITS 44

/* absolute distance: can be same for different client_id_check values
 * return value should have DISTANCE_INDEX_DISTANCE_BITS valid bits */
typedef uint64_t (*Assoc_distance_absolute_callback)(const Assoc *assoc, void *callback_data,
        const uint8_t *client_id_ref, const uint8_t *client_id_check);

/*****************************************************************************/

/* Central entry point for new associations: add a new candidate to the cache
 * returns 1 if entry is stored, 2 if existing entry was updated, 0 else */
uint8_t Assoc_add_entry(Assoc *assoc, const uint8_t *id, const IPPTs *ippts_send, const IP_Port *ipp_recv,
                        uint8_t used);

/*****************************************************************************/

typedef enum AssocCloseEntriesFlags {
    ProtoIPv4 = 1,
    ProtoIPv6 = 2,
    LANOk     = 4,
} AssocCloseEntriesFlags;

typedef struct Assoc_close_entries {
    void                              *custom_data;        /* given to distance functions */
    uint8_t                           *wanted_id;          /* the target client_id */
    uint8_t                            flags;              /* additional flags */

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

/* create: default sizes (6, 5 => 320 entries) */
Assoc *new_Assoc_default(const uint8_t *public_id);

/* create: customized sizes
 * total is (2^bits) * entries
 * bits should be between 2 and 15 (else it's trimmed)
 * entries will be reduced to the closest prime smaller or equal
 *
 * preferably bits should be large and entries small to ensure spread
 * in the search space (e. g. 5, 5 is preferable to 2, 41) */
Assoc *new_Assoc(size_t bits, size_t entries, const uint8_t *public_id);

/* public_id changed (loaded), update which entry isn't stored */
void Assoc_self_client_id_changed(Assoc *assoc, const uint8_t *public_id);

/* every 45s send out a getnodes() for a "random" bucket */
#define ASSOC_BUCKET_REFRESH 45

/* refresh bucket's data from time to time
 * this must be called only from DHT */
void do_Assoc(Assoc *assoc, DHT *dht);

/* destroy */
void kill_Assoc(Assoc *assoc);

#ifdef LOGGING
void Assoc_status(const Assoc *assoc);
#endif /* LOGGING */

#endif /* !__ASSOC_H__ */
