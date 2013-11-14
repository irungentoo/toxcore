
#include "DHT.h"
#include "assoc.h"
#include "ping.h"

#include "LAN_discovery.h"

#include "util.h"

/*
 *        BASIC OVERVIEW:
 *
 * Hash: The client_id is hashed with a local hash function.
 * Hashes are used in multiple places for searching.
 * Bucket: The first n bits of the client_id are used to
 * select a bucket. This speeds up sorting, but the more
 * important reason is to enforce a spread in the space of
 * client_ids available.
 *
 *
 * Candidates:
 *
 * Candidates are kept in buckets of hash tables. The hash
 * function is calculated from the client_id. Up to
 * HASH_COLLIDE_COUNT alternative positions are tried if
 * the inital position is already used by a different entry.
 * The collision function is multiplicative, not additive.
 *
 * A new candidate can bump an existing candidate, if it is
 * more "desirable": Seen beats Heard.
 */

/* candidates: number of bucket bits/buckets
 * if this is raised dramatically, DISTANCE_INDEX_DISTANCE_BITS
 * might have to be adjusted */
#define CANDIDATES_BUCKET_BITS 8
#define CANDIDATES_BUCKET_COUNT (1 << CANDIDATES_BUCKET_BITS)

/* candidates: number of candidates to keep PER BUCKET (should be a prime
 * for hash reasons, other primes e.g. 251, 509, 1021, 2039, 4093, 8191)
 * total number of candidates is therefore less than (BUCKET_COUNT * TO_KEEP),
 * given that a hash table is usually filling decently to around 50%, the
 * total long-term number of entries will be around 0.5 * 256 * 251 ~= 32k
 *
 * if this is raised dramatically, DISTANCE_INDEX_DISTANCE_BITS
 * might have to be adjusted */
#define CANDIDATES_TO_KEEP 251

/* candidates: alternative places for the same hash value */
#define HASH_COLLIDE_COUNT 5

/* candidates: bump entries: timeout values for seen/heard to be considered of value */
#define CANDIDATES_SEEN_TIMEOUT 1800
#define CANDIDATES_HEARD_TIMEOUT 600

/* distance/index: index size & access mask */
#define DISTANCE_INDEX_INDEX_BITS (64 - DISTANCE_INDEX_DISTANCE_BITS)
#define DISTANCE_INDEX_INDEX_MASK ((1 << DISTANCE_INDEX_INDEX_BITS) - 1)

/* types to stay consistent */
#if (CANDIDATES_BUCKET_BITS <= 16)
typedef uint16_t bucket_t;
#else
typedef uint32_t bucket_t;
#endif
typedef uint16_t usecnt_t;
typedef uint32_t hash_t;

/* abbreviations ... */
typedef Assoc_distance_relative_callback dist_rel_cb;
typedef Assoc_distance_absolute_callback dist_abs_cb;

/*
 * Client_data wrapped with additional data
 */
typedef struct Client_entry {
    hash_t             hash;

    /* shortcuts & rumors: timers and data */
    uint64_t           seen_at;
    uint64_t           heard_at;

    uint16_t           seen_family;
    uint16_t           heard_family;

    IP_Port            assoc_heard4;
    IP_Port            assoc_heard6;

    Client_data        client;
} Client_entry;

typedef struct candidates_bucket {
    Client_entry           list[CANDIDATES_TO_KEEP];  /* hashed list (with holes) */
} candidates_bucket;

typedef struct Assoc {
    DHT                   *dht;               /* for ping/getnodes */
    hash_t                 self_hash;         /* hash of self_client_id */
    uint8_t               *self_client_id;    /* don't store entries for this */

    /* association centralization: clients not in use */
    candidates_bucket      candidates[CANDIDATES_BUCKET_COUNT];
} Assoc;

/*****************************************************************************/
/*                             HELPER FUNCTIONS                              */
/*****************************************************************************/

/* the complete distance would be CLIENT_ID_SIZE long...
 * returns DISTANCE_INDEX_DISTANCE_BITS valid bits */
static uint64_t id_distance(Assoc *assoc, void *callback_data, uint8_t *id_ref, uint8_t *id_test)
{
    /* with BIG_ENDIAN, this would be a one-liner... */
    uint64_t retval = 0;

    uint8_t pos = 0, bits = DISTANCE_INDEX_DISTANCE_BITS;

    while (bits > 8) {
        uint8_t distance = abs((int8_t)id_ref[pos] ^ (int8_t)id_test[pos]);
        retval = (retval << 8) | distance;
        bits -= 8;
        pos++;
    }

    return (retval << bits) | ((id_ref[pos] ^ id_test[pos]) >> (8 - bits));
}

/* qsort() callback for a sorting by id_distance() values */
static int dist_index_comp(const void *a, const void *b)
{
    const uint64_t *_a = a;
    const uint64_t *_b = b;

    if (*_a < *_b)
        return -1;

    if (*_a > *_b)
        return 1;

    return 0;
}

/* get actual entry to a distance_index */
static Client_entry *dist_index_entry(Assoc *assoc, uint64_t dist_ind)
{
    if ((dist_ind & DISTANCE_INDEX_INDEX_MASK) == DISTANCE_INDEX_INDEX_MASK)
        return NULL;

    size_t offset = CANDIDATES_BUCKET_COUNT * CANDIDATES_TO_KEEP;
    uint32_t index = dist_ind & DISTANCE_INDEX_INDEX_MASK;

    if (index < offset) {
        bucket_t b_id = index / CANDIDATES_TO_KEEP;
        candidates_bucket *cnd_bckt = &assoc->candidates[b_id];
        size_t b_ix = index % CANDIDATES_TO_KEEP;
        Client_entry *entry = &cnd_bckt->list[b_ix];

        if (entry->hash)
            return entry;
    }

    return NULL;
}

/* get actual entry's client_id to a distance_index */
static uint8_t *dist_index_id(Assoc *assoc, uint64_t dist_ind)
{
    Client_entry *entry = dist_index_entry(assoc, dist_ind);

    if (entry)
        return entry->client.client_id;

    return NULL;
}

/* sorts first .. last, i.e. last is included */
static void dist_index_bubble(Assoc *assoc, uint64_t *dist_list, size_t first, size_t last, uint8_t *id,
                              void *custom_data, Assoc_distance_relative_callback dist_rel_func)
{
    size_t i, k;

    for (i = first; i <= last; i++) {
        uint8_t *id1 = dist_index_id(assoc, dist_list[i]);

        for (k = i + 1; k <= last; k++) {
            uint8_t *id2 = dist_index_id(assoc, dist_list[k]);

            if (id1 && id2)
                if (dist_rel_func(assoc, custom_data, id, id1, id2) == 2) {
                    uint64_t swap = dist_list[i];
                    dist_list[i] = dist_list[k];
                    dist_list[k] = swap;
                }
        }
    }
}

/* TODO: Check that there isn't a function like this elsewhere hidden.
 * E.g. the one which creates a handshake_id isn't usable for this, it must
 * always map the same ID to the same hash.
 *
 * Result is NOT MAPPED to CANDIDATES_TO_KEEP range, i.e. map before using
 * it for list access. */
static hash_t id_hash(uint8_t *id)
{
    uint32_t i, res = 0x19a64e82;

    for (i = 0; i < CLIENT_ID_SIZE; i++)
        res = ((res << 1) ^ (res >> 30)) ^ id[i];

    /* can't have zero as hash, a) marks an unused spot,
     * and b) slots for collision are multiplied, for
     * the latter reason also remap 1 .. 7 */
    if ((res % CANDIDATES_TO_KEEP) < 8)
        res = res + (CANDIDATES_TO_KEEP >> 2);

    return res;
}

/* up to HASH_COLLIDE_COUNT calls to different spots,
 * result IS mapped to CANDIDATES_TO_KEEP range */
static hash_t hash_collide(hash_t hash)
{
    uint64_t hash64 = hash % CANDIDATES_TO_KEEP;
    hash64 = (hash64 * 101) % CANDIDATES_TO_KEEP;

    hash_t retval = hash64;

    /* this should never happen when CANDIDATES_TO_KEEP is prime and hash not a multiple
     * (id_hash() checks for a multiple and returns a different hash in that case)
     *
     * ( 1 .. (prime - 1) is a group over multiplication and every number has its inverse
     *   in the group, so no multiplication should ever end on zero as long neither
     *   of the two factors was zero-equivalent )
     *
     * BUT: because the usage of the word "never" invokes Murphy's law, catch it */
    if (!retval)
        retval = 1;

    return retval;
}

/* returns the "seen" assoc related to the ipp */
static IPPTsPng *entry_assoc(Client_entry *cl_entry, IP_Port *ipp)
{
    if (!cl_entry)
        return NULL;

    if (ipp->ip.family == AF_INET)
        return &cl_entry->client.assoc4;

    if (ipp->ip.family == AF_INET6)
        return &cl_entry->client.assoc6;

    return NULL;
}

/* returns the "heard" assoc related to the ipp */
static IP_Port *entry_heard_get(Client_entry *entry, IP_Port *ipp)
{
    if (ipp->ip.family == AF_INET)
        return &entry->assoc_heard4;
    else if (ipp->ip.family == AF_INET6)
        return &entry->assoc_heard6;
    else
        return NULL;
}

/* store a "heard" entry
 * overwrites empty entry, does NOT overwrite non-LAN ip with
 * LAN ip
 *
 * returns 1 if the entry did change */
static int entry_heard_store(Client_entry *entry, IPPTs *ippts)
{
    if (!entry || !ippts)
        return 0;

    if (!ipport_isset(&ippts->ip_port))
        return 0;

    IP_Port  *heard, *ipp = &ippts->ip_port;

    if (ipp->ip.family == AF_INET)
        heard = &entry->assoc_heard4;
    else if (ipp->ip.family == AF_INET6)
        heard = &entry->assoc_heard6;
    else
        return 0;

    if (ipport_equal(ipp, heard))
        return 0;

    if (!ipport_isset(heard)) {
        *heard = *ipp;
        entry->heard_at = ippts->timestamp;
        entry->heard_family = ipp->ip.family;
        return 1;
    }

    /* don't destroy a good address with a crappy one
     * (unless we're very timed out) */
    uint8_t LAN_ipp = LAN_ip(ipp->ip) == 0;
    uint8_t LAN_entry = LAN_ip(heard->ip) == 0;

    if (LAN_ipp && !LAN_entry && !is_timeout(entry->heard_at, CANDIDATES_HEARD_TIMEOUT))
        return 0;

    *heard = *ipp;
    entry->heard_at = ippts->timestamp;
    entry->heard_family = ipp->ip.family;

    return 1;
}

/* maps Assoc callback signature to id_closest() */
static int assoc_id_closest(Assoc *assoc, void *callback_data, uint8_t *client_id, uint8_t *client_id1,
                            uint8_t *client_id2)
{
    return id_closest(client_id, client_id1, client_id2);
}

static bucket_t id_bucket(uint8_t *id, uint8_t bits)
{
    /* return the first "bits" bits of id */
    bucket_t retval = 0;

    uint8_t pos = 0;

    while (bits > 8) {
        retval = (retval << 8) | id[pos++];
        bits -= 8;
    }

    return (retval << bits) | (id[pos] >> (8 - bits));
}

/*****************************************************************************/
/*                          CANDIDATES FUNCTIONS                             */
/*****************************************************************************/


static bucket_t candidates_id_bucket(uint8_t *id)
{
    return id_bucket(id, CANDIDATES_BUCKET_BITS);
}

static uint8_t candidates_search(Assoc *assoc, uint8_t *id, hash_t hash, Client_entry **entryptr)
{
    bucket_t bucket = candidates_id_bucket(id);
    candidates_bucket *cnd_bckt = &assoc->candidates[bucket];
    size_t coll, pos = hash % CANDIDATES_TO_KEEP;

    for (coll = 0; coll < HASH_COLLIDE_COUNT; pos = hash_collide(pos) , coll++) {
        Client_entry *entry = &cnd_bckt->list[pos];

        if (entry->hash == hash)
            if (id_equal(entry->client.client_id, id)) {
                *entryptr = entry;
                return 1;
            }
    }

    *entryptr = NULL;
    return 0;
}

static void candidates_update_assoc(Assoc *assoc, Client_entry *entry, IPPTs *ippts_send, IP_Port *ipp_recv)
{
    if (!assoc || !entry || !ippts_send)
        return;

    IPPTsPng *ipptsp = entry_assoc(entry, &ippts_send->ip_port);

    if (!ipptsp)
        return;

    /* do NOT do anything related to wanted, that's handled outside,
     * just update the assoc (in the most sensible way)
     */
    if (ipp_recv) {
        ipptsp->ip_port = ippts_send->ip_port;
        ipptsp->timestamp = ippts_send->timestamp;
        ipptsp->ret_ip_port = *ipp_recv;
        ipptsp->ret_timestamp = unix_time();

        entry->seen_at = unix_time();
        entry->seen_family = ippts_send->ip_port.ip.family;

        return;
    }

    entry_heard_store(entry, ippts_send);
}

static uint8_t candidates_create_internal(Assoc *assoc, hash_t hash, uint8_t *id, uint8_t seen,
        bucket_t *bucketptr, size_t *posptr)
{
    if (!assoc || !id || !bucketptr ||  !posptr)
        return 0;

    bucket_t bucket = candidates_id_bucket(id);
    candidates_bucket *cnd_bckt = &assoc->candidates[bucket];

    size_t coll, pos = hash % CANDIDATES_TO_KEEP, check;
    size_t pos_check[6];

    memset(pos_check, 0, sizeof(pos_check));

    for (coll = 0; coll < HASH_COLLIDE_COUNT; pos = hash_collide(pos) , coll++) {
        Client_entry *entry = &cnd_bckt->list[pos];

        /* unset */
        if (!entry->hash) {
            *bucketptr = bucket;
            *posptr = pos;

            return 1;
        }

        /* 0. bad
         * 1. seen bad, heard good
         * 2. seen good */
        if (!is_timeout(entry->seen_at, CANDIDATES_SEEN_TIMEOUT))
            check = 2;
        else if (!is_timeout(entry->heard_at, CANDIDATES_HEARD_TIMEOUT))
            check = 1;
        else
            check = 0;

        if (!pos_check[check])
            pos_check[check] = pos + 1;
    }

    /* seen can bump heard&bad, heard can bump only bad */
    size_t i, pos_max = seen ? 2 : 1;

    for (i = 0; i < pos_max; i++)
        if (pos_check[i]) {
            *bucketptr = bucket;
            *posptr = pos_check[i] - 1;

            return 1;
        }

    return 0;
}

static void candidates_create_new(Assoc *assoc, hash_t hash, uint8_t *id,
                                  IPPTs *ippts_send, IP_Port *ipp_recv)
{
    if (!assoc || !id || !ippts_send)
        return;

    bucket_t bucket;
    size_t pos;

    if (!candidates_create_internal(assoc, hash, id, ipp_recv != NULL, &bucket, &pos))
        return;

    candidates_bucket *cnd_bckt = &assoc->candidates[bucket];
    Client_entry *entry = &cnd_bckt->list[pos];
    memset(entry, 0, sizeof(*entry));

    IPPTsPng *ipptsp = entry_assoc(entry, &ippts_send->ip_port);

    if (!ipptsp)
        return;

    entry->hash = hash;
    id_copy(entry->client.client_id, id);

    if (ipp_recv && !ipport_isset(ipp_recv))
        ipp_recv = NULL;

    if (ipp_recv) {
        entry->seen_at = unix_time();
        entry->seen_family = ippts_send->ip_port.ip.family;

        ipptsp->ip_port = ippts_send->ip_port;
        ipptsp->timestamp = ippts_send->timestamp;
        ipptsp->ret_ip_port = *ipp_recv;
        ipptsp->ret_timestamp = unix_time();
    } else {
        IP_Port *heard = entry_heard_get(entry, &ippts_send->ip_port);

        if (heard) {
            entry->heard_at = ippts_send->timestamp;
            entry->heard_family = ippts_send->ip_port.ip.family;

            *heard = ippts_send->ip_port;
        }
    }
}

/*****************************************************************************/

static void client_id_self_update(Assoc *assoc)
{
    if (assoc->self_hash || !assoc->self_client_id)
        return;

    if (!assoc->self_hash) {
        size_t i, sum = 0;

        for (i = 0; i < crypto_box_PUBLICKEYBYTES; i++)
            sum |= assoc->self_client_id[i];

        if (!sum)
            return;

        assoc->self_hash = id_hash(assoc->self_client_id);
    }

#ifdef LOGGING
    loglog("assoc: id is now set, purging cache of self-references...\n");
#endif

    /* if we already added some (or loaded some) entries,
     * look and remove if we find a match
     */
    bucket_t b_id = candidates_id_bucket(assoc->self_client_id);
    candidates_bucket *cnd_bckt = &assoc->candidates[b_id];
    size_t i, pos = assoc->self_hash % CANDIDATES_TO_KEEP;

    for (i = 0; i < HASH_COLLIDE_COUNT; pos = hash_collide(pos), i++) {
        Client_entry *entry = &cnd_bckt->list[pos];

        if (entry->hash == assoc->self_hash)
            if (id_equal(entry->client.client_id, assoc->self_client_id))
                entry->hash = 0;
    }
}

/*****************************************************************************/
/*                            TRIGGER FUNCTIONS                              */
/*****************************************************************************/

/* Central entry point for new associations: add a new candidate to the cache
 * seen should be 0 (zero), if the candidate was announced by someone else,
 * seen should be 1 (one), if there is confirmed connectivity (a definite response)
 */
void Assoc_add_entry(Assoc *assoc, uint8_t *id, IPPTs *ippts_send, IP_Port *ipp_recv)
{
    if (!assoc || !id || !ippts_send)
        return;

    if (!assoc->self_hash) {
        client_id_self_update(assoc);

        if (!assoc->self_hash)
            return;
    }

    if (!ipport_isset(&ippts_send->ip_port))
        return;

    if (ipp_recv && !ipport_isset(ipp_recv))
        ipp_recv = NULL;

    hash_t hash = id_hash(id);

    if (hash == assoc->self_hash)
        if (id_equal(id, assoc->self_client_id))
            return;

    /* if it's new:
     * callback, if there's desire, add to clients, else to candidates
     *
     * if it's "old":
     *    if it's client: refresh
     *    if it's candidate:
     *       if !ipp_recv, refresh
     *       if ipp_recv: callback, if there's desire, move to candidates
     */
    Client_entry *cnd_entry;

    if (!candidates_search(assoc, id, hash, &cnd_entry))
        candidates_create_new(assoc, hash, id, ippts_send, ipp_recv);
    else
        candidates_update_assoc(assoc, cnd_entry, ippts_send, ipp_recv);
}

/*****************************************************************************/
/*                               MAIN USE                                    */
/*****************************************************************************/

uint8_t Assoc_get_close_entries(Assoc *assoc, Assoc_close_entries *state)
{
    if (!assoc || !state || !state->wanted_id || !state->result)
        return 0;

    if (!assoc->self_hash) {
        client_id_self_update(assoc);

        if (!assoc->self_hash)
            return 0;
    }

    if (!state->distance_relative_func)
        state->distance_relative_func = assoc_id_closest;

    if (!state->distance_absolute_func)
        state->distance_absolute_func = id_distance;

    size_t clients_offset = CANDIDATES_BUCKET_COUNT * CANDIDATES_TO_KEEP;
    size_t dist_list_len = clients_offset;
    uint64_t dist_list[dist_list_len];
    memset(dist_list, ~0, dist_list_len * sizeof(dist_list[0]));
    bucket_t b;
    size_t i;

    for (b = 0; b < CANDIDATES_BUCKET_COUNT; b++) {
        candidates_bucket *cnd_bckt = &assoc->candidates[b];

        for (i = 0; i < CANDIDATES_TO_KEEP; i++) {
            Client_entry *entry = &cnd_bckt->list[i];

            if (entry->hash) {
                uint64_t dist = state->distance_absolute_func(assoc, state->custom_data, state->wanted_id, entry->client.client_id);
                uint32_t index = b * CANDIDATES_TO_KEEP + i;
                dist_list[index] = (dist << DISTANCE_INDEX_INDEX_BITS) | index;
            }
        }
    }

    qsort(dist_list, dist_list_len, sizeof(dist_list[0]), dist_index_comp);

    /* ok, ok, it's not *perfectly* sorted, because we used an absolute distance
     * go over the result and see if we need to "smoothen things out"
     * because those should be only very few and short streaks, the worst regularly
     * used sorting function aka bubble sort is used */
    uint64_t dist_prev = ~0;
    size_t ind_prev = ~0, ind_curr;
    size_t len = 1;

    for (ind_curr = 0; ind_curr < dist_list_len; ind_curr++) {
        /* sorted increasingly, so an invalid entry marks the end */
        if ((dist_list[ind_curr] & DISTANCE_INDEX_INDEX_MASK) == DISTANCE_INDEX_INDEX_MASK)
            break;

        uint64_t dist_curr = dist_list[ind_curr] >> DISTANCE_INDEX_INDEX_BITS;

        if (dist_prev == dist_curr)
            len++;
        else {
            if (len > 1)
                dist_index_bubble(assoc, dist_list, ind_prev, ind_curr - 1, state->wanted_id, state->custom_data,
                                  state->distance_relative_func);

            dist_prev = dist_curr;
            ind_prev = ind_curr;
            len = 1;
        }
    }

    if (len > 1)
        dist_index_bubble(assoc, dist_list, ind_prev, ind_curr - 1, state->wanted_id, state->custom_data,
                          state->distance_relative_func);

    /* ok, now dist_list is a strictly ascending sorted list of nodes
     * a) extract CLOSE_QUOTA_USED clients, not timed out
     * b) extract (1 - QUOTA) (better!) clients & candidates, not timed out
     * c) save candidates which would be better, if contact can be established */
    size_t client_quota_good = 0, pos = 0;
    size_t client_quota_max = state->count_good;

    ssize_t taken_last = - 1;

    for (i = 0; (i < dist_list_len) && (pos < state->count); i++) {
        Client_entry *entry = dist_index_entry(assoc, dist_list[i]);

        if (entry && entry->hash) {
            if (client_quota_good >= client_quota_max) {
                state->result[pos++] = &entry->client;
                taken_last = i;
            } else if (!is_timeout(entry->seen_at, BAD_NODE_TIMEOUT)) {
                state->result[pos++] = &entry->client;
                client_quota_good++;
                taken_last = i;
            }
        }
    }

    /* if we had not enough valid entries the list might still not be filled.
     *
     * start again from last taken client, but leave out any requirement
     */
    if (pos < state->count) {
        for (i = taken_last + 1; (i < dist_list_len) && (pos < state->count); i++) {
            Client_entry *entry = dist_index_entry(assoc, dist_list[i]);

            if (entry && entry->hash)
                state->result[pos++] = &entry->client;
        }
    }

    return pos;
}

/*****************************************************************************/
/*                     GLOBAL STRUCTURE FUNCTIONS                            */
/*****************************************************************************/

/* create */
Assoc *new_Assoc(DHT *dht)
{
    Assoc *assoc = calloc(1, sizeof(*assoc));

    if (!assoc)
        return NULL;

    /* dht MAY be NULL! (e.g. testing) */
    if (dht) {
        assoc->dht = dht;
        assoc->self_client_id = dht->c->self_public_key;
    } else {
        assoc->self_client_id = malloc(CLIENT_ID_SIZE);
        assoc->self_client_id[0] = 42;
    }

    return assoc;
}

/* own client_id, assocs for this have to be ignored */
void Assoc_self_client_id_changed(Assoc *assoc)
{
    if (assoc) {
        assoc->self_hash = 0;
        client_id_self_update(assoc);
    }
}

/* destroy */
void kill_Assoc(Assoc *assoc)
{
    /* nothing dynamic left in trim */
    free(assoc);
}
