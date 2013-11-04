
#include "DHT.h"
#include "assoc.h"
#include "ping.h"

#include "LAN_discovery.h"

#include "util.h"

/*
 *        BASIC OVERVIEW:
 *
 * "Association" is short for "an ID <=> IP(s) association".
 *
 * Hash: The client_id is hashed with a local hash function.
 * Hashes are used in multiple places for searching.
 * Bucket: The first n bits of the client_id are used to
 * select a bucket. This speeds up sorting, but the more
 * important reason is to enforce a spread in the space of
 * client_ids available.
 *
 * The module keeps two types of entries:
 * - clients
 * - candidates
 *
 * A candidate is an association without any restrictions.
 * A client is an association which is:
 * a) proven as connectable (i.e. validated with a response),
 * b) not timed out, AND
 * c) in use by another module
 *
 * A candidate can be a) & b) as well. If desired, a candidate
 * will be converted into a client if a) & b) are valid.
 *
 *
 * Clients:
 *
 * Clients are kept in a list where they keep fixed indices,
 * i.e. an entry is accessible under an index as long as the
 * client is valid, independent of any other client being
 * created or destroyed.
 *
 * Additionally, a second group of references exist for the
 * clients to allow quick searching:
 * The clients are distributed across buckets with each
 * containing a list sorted by hash. Those are referencing
 * into the fixed list.
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
 * more "desirable": Wanted by an external, Heard (i.e. recently
 * another node promoted its existence), Seen (i.e. a verified
 * connectable node).
 */

static uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a > b ? b : a;
}

/* when a new node is added, the close list has to be filled
 * ideally, we'd want to fill it immediately with the perfect set of nodes
 * but perfection is relative...
 * imperfect solution:
 * - fill (at least) CLOSE_QUOTA_USED of the spots with nodes already in use (if we have that many)
 * - fill the remaining spots with nodes that talked to us less than CANDIDATES_SEEN_TIMEOUT ago
 *        (but only if they are better than the nodes from the used list)
 *
 * in addition:
 * - send CLOSE_QUOTA_WANTED nodes ping&getnodes requests (but only if they are better than the
 *   nodes inserted)
 */

/* factor 1: (that part of a node's close list) shall be filled with clients
 * already in use, i.e. most definitely reachable
 * if we simply don't have that many, additional convertible candidates
 * (i.e. seen and not timed out) are converted into clients */
#define CLOSE_QUOTA_USED 0.6

/* factor 2: (that part of a node's close list) not convertible candidates
 * better than those used shall be asked about ideal close nodes */
#define CLOSE_QUOTA_WANTED 0.2

/* clients: number of bucket bits/buckets */
#define CLIENTS_BUCKET_BITS 4
#define CLIENTS_BUCKET_COUNT (1 << CLIENTS_BUCKET_BITS)

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
#define HASH_COLLIDE_COUNT 4

/* candidates: bump entries: timeout values for seen/heard to be considered of value */
#define CANDIDATES_SEEN_TIMEOUT 1800
#define CANDIDATES_HEARD_TIMEOUT 900

/* distance/index: index size & access mask */
#define DISTANCE_INDEX_INDEX_BITS (64 - DISTANCE_INDEX_DISTANCE_BITS)
#define DISTANCE_INDEX_INDEX_MASK ((1 << DISTANCE_INDEX_INDEX_BITS) - 1)

/* types to stay consistent */
#if ((CLIENTS_BUCKET_BITS <= 16) && (CANDIDATES_BUCKET_BITS <= 16))
typedef uint16_t bucket_t;
#else
typedef uint32_t bucket_t;
#endif
typedef uint16_t usecnt_t;
typedef uint32_t hash_t;

/* abbreviations ... */
typedef DHT_assoc_distance_relative_callback dist_rel_cb;
typedef DHT_assoc_distance_absolute_callback dist_abs_cb;
typedef DHT_assoc_check_callbacks check_cbs;

#ifdef DHT_ASSOC_HANDLER_FULL_DONE
typedef struct candidate_ref {
    hash_t    hash;

    size_t    pos;
    bucket_t  bucket;
} candidate_ref;

typedef struct ID_Nodes {
    uint8_t        *client_id;             /* assumed to be CLIENT_ID_SIZE large */
    size_t         *close_nodes_used;      /* indices into the used nodes array + 1, or 0 */
    candidate_ref  *close_nodes_wanted;    /* references into the candidates arrays */
} ID_Nodes;
#endif

typedef struct Handler {
    char                *description;      /* if not NULL, a description (for logging/debugging/etc.) */
    void                *data_cb;          /* second argument to any callback */
    DHT_assoc_callbacks *callbacks;        /* callbacks */

    dist_rel_cb          dist_rel_func;    /* shortcut */

#if DHT_ASSOC_HANDLER_FULL_DONE
    size_t               group_capacity;
    DHT_assoc_ID_Nodes **groups;
    size_t               close_count;      /* number of close nodes wanted */
#endif
} Handler;

/*
 * Client_data wrapped with the additional data for
 * candidate/client handling
 */
typedef struct Client_entry {
    hash_t         hash;

    /* rumors: timers and data */
    uint64_t       seen_at;
    uint64_t       heard_at;

    uint16_t       seen_family;
    uint16_t       heard_family;

    IP_Port        assoc_heard4;
    IP_Port        assoc_heard6;

    union {
        struct {
            usecnt_t   used_cl;       /* clients: usage counter */
            uint8_t    bad_cl;        /* clients: users were informed that node has gone bad */
        };

        struct {
            uint64_t       wanted_at_cnd;   /* candidates: timestamp for wanted request */
            uint8_t        wanted_req_cnd;  /* candidates: counts up for attempts to convert to client */
        };
    };

    Client_data    client;
} Client_entry;

typedef struct index_entry {
    size_t        fixed;  /* position in fixed, real index, not +1 ! */
    Client_entry *entry;
} index_entry;

typedef struct clients_sorted_bucket {
    size_t              capacity;          /* list: space (in structs) in this bucket */
    size_t              num;               /* list: used num (in structs) in this bucket */
    index_entry        *index_entry_list;  /* list: pair of (index into clients_fixed, entry ptr) */
} clients_sorted_bucket;

typedef struct candidates_bucket {
    Client_entry        list[CANDIDATES_TO_KEEP];  /* hashed list (with holes) */
} candidates_bucket;

typedef struct DHT_assoc {
    DHT                    *dht;               /* for ping/getnodes */
    hash_t                  self_hash;         /* hash of self_client_id */
    uint8_t                 self_client_id[CLIENT_ID_SIZE]; /* don't store entries for this */

    struct {
        size_t              capacity;          /* outside users: allocated space */
        Handler           **list;              /* outside users: list (movable) */
    } handlers;

    struct {
        size_t              capacity;          /* allocated */
        size_t              num;               /* used (not necessarily 0..num -1!) */
        check_cbs          *funcs_list;        /* an entry or NULL (not movable) */
        void              **data_list;         /* an entry or NULL (not movable) */
    } candidate_callbacks;

    /* association centralization: clients in use */
    struct {
        size_t              capacity;          /* allocated count (in structs) */
        Client_entry      **list;              /* clients in active use or NULL (not movable) */
    } clients_fixed;

    clients_sorted_bucket   clients_sorted[CLIENTS_BUCKET_COUNT];

    /* association centralization: clients not in use */
    candidates_bucket       candidates[CANDIDATES_BUCKET_COUNT];

    /* timestamps for DHT_assoc_do() */
    struct {
        uint64_t            bad;     /* client has gone "bad" (BAD_NODE_TIMEOUT) */
        uint64_t            kill;    /* client is considered "terminally" invalid, push it out (KILL_NODE_TIMEOUT) */
        uint64_t            wanted;  /* send pings to wanted candidates in the hope of promoting them to clients */
    } worker_do;
} DHT_assoc;

/*****************************************************************************/
/*                             HELPER FUNCTIONS                              */
/*****************************************************************************/

/* the complete distance would be CLIENT_ID_SIZE long...
 * returns DISTANCE_INDEX_DISTANCE_BITS valid bits */
static uint64_t id_distance(DHT_assoc *dhtassoc, void *callback_data, uint8_t *id_ref, uint8_t *id_test)
{
    /* with BIG_ENDIAN, this would be a one-liner... */
    uint64_t retval = 0;

    uint8_t pos = 0, bits = DISTANCE_INDEX_DISTANCE_BITS;

    while (bits > 8) {
        retval = (retval << 8) | (id_ref[pos] ^ id_test[pos]);
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
static Client_entry *dist_index_entry(DHT_assoc *dhtassoc, uint64_t dist_ind)
{
    if ((dist_ind & DISTANCE_INDEX_INDEX_MASK) == DISTANCE_INDEX_INDEX_MASK)
        return NULL;

    size_t offset = CANDIDATES_BUCKET_COUNT * CANDIDATES_TO_KEEP;
    uint32_t index = dist_ind & DISTANCE_INDEX_INDEX_MASK;

    if (index < offset) {
        bucket_t b_id = index / CANDIDATES_TO_KEEP;
        candidates_bucket *cnd_bckt = &dhtassoc->candidates[b_id];
        size_t b_ix = index % CANDIDATES_TO_KEEP;
        Client_entry *entry = &cnd_bckt->list[b_ix];

        if (entry->hash)
            return entry;

    } else {
        size_t ix = index - offset;

        return dhtassoc->clients_fixed.list[ix];
    }

    return NULL;
}

/* get actual entry's client_id to a distance_index */
static uint8_t *dist_index_id(DHT_assoc *dhtassoc, uint64_t dist_ind)
{
    Client_entry *entry = dist_index_entry(dhtassoc, dist_ind);

    if (entry)
        return entry->client.client_id;

    return NULL;
}

/* sorts first .. last, i.e. last is included */
static void dist_index_bubble(DHT_assoc *dhtassoc, uint64_t *dist_list, size_t first, size_t last, uint8_t *id,
                              void *custom_data, DHT_assoc_distance_relative_callback dist_rel_func)
{
    size_t i, k;

    for (i = first; i <= last; i++) {
        uint8_t *id1 = dist_index_id(dhtassoc, dist_list[i]);

        for (k = i + 1; k <= last; k++) {
            uint8_t *id2 = dist_index_id(dhtassoc, dist_list[k]);

            if (id1 && id2)
                if (dist_rel_func(dhtassoc, custom_data, id, id1, id2) == 2) {
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
static int entry_heard_store(Client_entry *entry, IP_Port *ipp)
{
    if (!entry || !ipp)
        return 0;

    if (!ipport_isset(ipp))
        return 0;

    IP_Port  *heard;

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
        entry->heard_at = unix_time();
        entry->heard_family = ipp->ip.family;
        return 1;
    }

    /* don't destroy a good address with a crappy one */
    uint8_t LAN_ipp = LAN_ip(ipp->ip) == 0;
    uint8_t LAN_entry = LAN_ip(heard->ip) == 0;

    if (LAN_ipp && !LAN_entry)
        return 0;

    *heard = *ipp;
    entry->heard_at = unix_time();
    entry->heard_family = ipp->ip.family;

    return 1;
}

/*
 * retrieve (the best of) whatever IP_Port the entry offers
 *
 * flags:
 * 1: if set, prefer youngest of seen and heard, else prefer seen over heard
 * 2: if set, consider LAN as equal choice, else prefer non-LAN to LAN
 * (seen > heard) dominates over (non-LAN > LAN) if both flags are set
 */
static IP_Port *entry_ipport_get(Client_entry *entry, uint8_t flags)
{
    if (!entry || (!entry->seen_at && !entry->heard_at))
        return NULL;

    IP_Port *ptrs[4];
    size_t i, what = 0, found = 0;

    for (i = 0; i < 2; i++) {
        if (i == 0) {
            if (entry->heard_at)
                what = 1;

            if (entry->seen_at)
                if (!(flags & 1) || entry->seen_at > entry->heard_at)
                    what = 2;
        } else if (i == 1)
            what = 3 - what;

        if (what == 2) {
            if (entry->seen_at) {
                if (entry->seen_family == AF_INET) {
                    ptrs[found++] = &entry->client.assoc4.ip_port;

                    if (ipport_isset(&entry->client.assoc6.ip_port))
                        ptrs[found++] = &entry->client.assoc6.ip_port;
                } else if (entry->seen_family == AF_INET6) {
                    ptrs[found++] = &entry->client.assoc4.ip_port;

                    if (ipport_isset(&entry->client.assoc4.ip_port))
                        ptrs[found++] = &entry->client.assoc4.ip_port;
                }
            }
        } else if (what == 1) {
            if (entry->heard_at) {
                if (entry->heard_family == AF_INET) {
                    ptrs[found++] = &entry->assoc_heard4;

                    if (ipport_isset(&entry->assoc_heard6))
                        ptrs[found++] = &entry->assoc_heard6;
                } else if (entry->heard_family == AF_INET6) {
                    ptrs[found++] = &entry->assoc_heard6;

                    if (ipport_isset(&entry->assoc_heard4))
                        ptrs[found++] = &entry->assoc_heard4;
                }
            }
        }
    }

    if (!found)
        return NULL;

    if (flags & 2) {
        if (ipport_isset(ptrs[0]))
            return ptrs[0];

        return NULL;
    }

    for (i = 0; i < found; i++)
        if (ipport_isset(ptrs[i]))
            if (LAN_ip(ptrs[i]->ip) < 0)
                return ptrs[i];

    if (ipport_isset(ptrs[0]))
        return ptrs[0];

    return NULL;
}

/* maps DHT_assoc callback signature to id_closest() */
static int assoc_id_closest(DHT_assoc *dhtassoc, void *callback_data, uint8_t *client_id, uint8_t *client_id1,
                            uint8_t *client_id2)
{
    return id_closest(client_id, client_id1, client_id2);
}

static uint32_t handlers_entry_wanted(DHT_assoc *dhtassoc, hash_t hash, uint8_t *id, uint8_t seen, IP_Port *ipp)
{
    if (!dhtassoc || !id)
        return 0;

    size_t i, wanted = 0;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler)
            continue;

        DHT_assoc_check_new_callback check_new_func = handler->callbacks->check_funcs.check_new_func;

        if (check_new_func)
            wanted += check_new_func(dhtassoc, handler->data_cb, hash, id, seen, ipp);
    }

    return wanted;
}

static void handlers_entry_deleting(DHT_assoc *dhtassoc, size_t index, Client_entry *entry)
{
    if (!dhtassoc || !entry)
        return;

    size_t i;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler)
            continue;

        DHT_assoc_check_delete_callback check_delete_func = handler->callbacks->check_funcs.check_delete_func;

        if (check_delete_func)
            check_delete_func(dhtassoc, handler->data_cb, index, &entry->client);
    }
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
/*                            CLIENTS FUNCTIONS                              */
/*****************************************************************************/

static bucket_t clients_id_bucket(uint8_t *id)
{
    return id_bucket(id, CLIENTS_BUCKET_BITS);
}

static void clients_update_usable(DHT_assoc *dhtassoc, size_t index, Client_entry *entry)
{
    if (!entry)
        return;

    uint32_t used = entry->used_cl;
    size_t i;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler)
            continue;

        DHT_assoc_check_usable_callback check_usable_func = handler->callbacks->check_funcs.check_usable_func;

        if (check_usable_func)
            used += check_usable_func(dhtassoc, handler->data_cb, index, &entry->client);
    }

    entry->used_cl = used;

    if (entry->used_cl < used) {
        /* crap. overflow: set to max. storable */
        entry->used_cl = ~0;
    }
}

static void clients_update_usage(DHT_assoc *dhtassoc, size_t index, Client_entry *entry)
{
    if (!entry)
        return;

    uint32_t used = 0;
    size_t i;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler)
            continue;

        DHT_assoc_check_usage_callback check_usage_func = handler->callbacks->check_funcs.check_usage_func;

        if (check_usage_func)
            used += check_usage_func(dhtassoc, handler->data_cb, index, &entry->client);
    }

    entry->used_cl = used;

    if (entry->used_cl < used) {
        /* crap. overflow: set to max. storable */
        entry->used_cl = ~0;
    }
}

/* find the range of first..last in index_entry_list with the same hash
 *
 *  return 1, ranges on success
 *  return 0 on error/not found */
static uint8_t clients_search_helper(hash_t hash, size_t num, index_entry *index_entry_list, size_t *first,
                                     size_t *last)
{
    /* this is essentially just three binary searches
     * can't use bsearch for the latter two though, and
     * the first bsearch already adjusts the search space,
     * so no using bsearch() */

    /* corner case: field without content */
    if (!num)
        return 0;

    /* corner case: hash outside [low .. high] */
    if ((hash < index_entry_list[0].entry->hash) ||
            (index_entry_list[num - 1].entry->hash < hash))
        return 0;

    size_t low = 0;
    size_t middle = (num - 1) >> 1;
    size_t high = num - 1;

    if ((index_entry_list[low].entry->hash < hash) && (hash < index_entry_list[high].entry->hash))
        while (index_entry_list[middle].entry->hash != hash) {
            middle = (low + high) >> 1;

            if (index_entry_list[middle].entry->hash < hash) {
                if (low != middle)
                    low = middle;
                else
                    return 0;
            } else if (index_entry_list[middle].entry->hash > hash) {
                if (high != middle)
                    high = middle;
                else
                    return 0;
            }
        }
    else if (index_entry_list[low].entry->hash == hash)
        middle = low;
    else if (index_entry_list[high].entry->hash == hash)
        middle = high;

    /* middle, low or high are at hash positions,
     * if the corners of the array were at the hash,
     * middle has to be initialized here, because the loop
     * was never entered */
    if (index_entry_list[middle].entry->hash != hash) {
        if (index_entry_list[low].entry->hash == hash)
            middle = low;

        if (index_entry_list[high].entry->hash == hash)
            middle = high;
    }

    if (index_entry_list[middle].entry->hash == hash) {
        /* expand to low/high */
        size_t lowmiddle = middle;

        if ((lowmiddle > 0) && (index_entry_list[lowmiddle - 1].entry->hash == hash)) {
            lowmiddle--;

            while (lowmiddle >= low) {
                uint32_t check = (low + lowmiddle) >> 1;

                if (index_entry_list[check].entry->hash == hash) {
                    if (lowmiddle != check)
                        lowmiddle = check;
                    else
                        break;
                } else if (low != check)
                    low = check;
                else
                    break;
            }
        }

        size_t highmiddle = middle;

        if ((highmiddle < num - 1) && (index_entry_list[highmiddle + 1].entry->hash == hash)) {
            highmiddle++;

            while (highmiddle <= high) {
                uint32_t check = (highmiddle + high + 1) >> 1;

                if (index_entry_list[check].entry->hash == hash) {
                    if (highmiddle != check)
                        highmiddle = check;
                    else
                        break;
                } else if (high != check)
                    high = check;
                else
                    break;
            }
        }

        *first = lowmiddle;
        *last = highmiddle;
        return 1;
    }

    return 0;
}

/* search clients for hash/id
 *
 *  returns 1 on success, 0 on error */
static uint8_t clients_search(DHT_assoc *dhtassoc, uint8_t *id, hash_t hash, size_t *fixed_index,
                              Client_entry **entryptr, bucket_t *sorted_bucket, size_t *sorted_index)
{
    if (!dhtassoc || !id)
        return 0;

    /* either fixed_index and entry are set, or sorted_bucket and sorted_index:
     * it's the negation of
     * ( fixed_index &&  entry && !sorted_bucket && !sorted_index) ||
     * (!fixed_index && !entry &&  sorted_bucket &&  sorted_index)
     */
    if ((fixed_index || entryptr || !sorted_bucket || !sorted_index) &&
            (!fixed_index || !entryptr || sorted_bucket || sorted_index))
        return 0;

    /* nothing ever added */
    if (!dhtassoc->clients_fixed.capacity)
        return 0;

    bucket_t b_id = clients_id_bucket(id);
    clients_sorted_bucket *bucket = &dhtassoc->clients_sorted[b_id];

    if (!bucket->num)
        return 0;

    /* perform binary search */
    index_entry *index_entry_list = bucket->index_entry_list;
    size_t i, first, last;

    if (!clients_search_helper(hash, bucket->num, index_entry_list, &first, &last))
        return 0;

    for (i = first; i <= last; i++)
        if (index_entry_list[i].entry->hash == hash)
            if (id_equal(id, index_entry_list[i].entry->client.client_id)) {
                size_t pos = index_entry_list[i].fixed;

                if (fixed_index && entryptr) {
                    *fixed_index = pos + 1;
                    *entryptr = dhtassoc->clients_fixed.list[pos];
                }

                if (sorted_bucket && sorted_index) {
                    *sorted_bucket = b_id;
                    *sorted_index = i;
                }

                return 1;
            }

    return 0;
}

/* return 1, *index, *targetptr on success
 * return 0, 0, NULL on error
 */
static uint8_t clients_create_internal(DHT_assoc *dhtassoc, Client_entry *source, size_t *index,
                                       Client_entry **targetptr)
{
    if (!dhtassoc || !source || !index || !targetptr)
        return 0;

    *index = 0;
    *targetptr = NULL;

    /* assume that the outside checked for existence of an entry with negative result */
    Client_entry *target = malloc(sizeof(*target));

    if (!target)
        return 0;

    /* work, work, work... */
    size_t i, fixed = 0;

    for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
        if (!dhtassoc->clients_fixed.list[i])
            fixed = i + 1;
    }

    if (fixed)
        fixed--;
    else {
        size_t capacity_old = dhtassoc->clients_fixed.capacity;
        size_t capacity_new = capacity_old + 32;
        Client_entry **fixed_entries = realloc(dhtassoc->clients_fixed.list, capacity_new * sizeof(Client_entry *));

        if (!fixed_entries) {
            free(target);
            return 0;
        }

        memset(&fixed_entries[capacity_old], 0, (capacity_new - capacity_old) * sizeof(*fixed_entries));
        dhtassoc->clients_fixed.capacity = capacity_new;
        dhtassoc->clients_fixed.list = fixed_entries;

        fixed = capacity_old;
    }

    bucket_t b_id = clients_id_bucket(source->client.client_id);
    clients_sorted_bucket *cl_bckt = &dhtassoc->clients_sorted[b_id];

    if (cl_bckt->num == cl_bckt->capacity) {
        size_t capacity_old = cl_bckt->capacity;
        size_t capacity_new = capacity_old + 32;
        index_entry *ies = realloc(cl_bckt->index_entry_list, capacity_new * sizeof(*ies));

        if (!ies) {
            free(target);
            return 0;
        }

        memset(&ies[capacity_old], 0, (capacity_new - capacity_old) * sizeof(*ies));
        cl_bckt->capacity = capacity_new;
        cl_bckt->index_entry_list = ies;
    }

    /* prepare it: just copy, additional adjustments happen after internal creation */
    memcpy(target, source, sizeof(Client_entry));

    /* store it: fixed list */
    dhtassoc->clients_fixed.list[fixed] = target;

    /* store it: sorted list */
    size_t num = cl_bckt->num, pos = num + 1;

    if (!num)
        pos = 0;
    else if (target->hash < cl_bckt->index_entry_list[0].entry->hash) {
        pos = 0;
    } else if (target->hash > cl_bckt->index_entry_list[num - 1].entry->hash) {
        pos = num;
    } else {
        /* binary-search right spot */
        size_t low = 0, high = num - 1, middle = (low + high) >> 1;

        while (low < high) {
            size_t middle = (high + low) >> 1;

            if (target->hash < cl_bckt->index_entry_list[middle].entry->hash) {
                if (high != middle)
                    high = middle;
                else
                    break;
            } else if (target->hash > cl_bckt->index_entry_list[middle].entry->hash) {
                if (low != middle)
                    low = middle;
                else
                    break;
            } else
                break;
        }

        /* may have broken out at one spot off */

        /* too high */
        while ((middle > 0) && (target->hash < cl_bckt->index_entry_list[middle - 1].entry->hash)) {
            middle--;
        }

        /* too low */
        while ((middle < num) && (target->hash > cl_bckt->index_entry_list[middle + 1].entry->hash)) {
            middle++;
        }

        pos = middle;
    }

    if (pos < num) {
        /* move the array "end" one piece forward:
         * everything from pos .. num - 1 moves to pos + 1 .. num */
        size_t movelen = (num - pos) * sizeof(index_entry);
        memmove(&cl_bckt->index_entry_list[pos + 1], &cl_bckt->index_entry_list[pos], movelen);
    }

    index_entry *ie = &cl_bckt->index_entry_list[pos];
    ie->fixed = fixed;
    ie->entry = target;

    cl_bckt->num++;

    *index = fixed + 1;
    *targetptr = target;

    return 1;
}

/* keeps associations from candidate */
static uint8_t clients_create_from_candidates(DHT_assoc *dhtassoc, Client_entry *cnd_entry, size_t *index,
        Client_entry **cl_entryptr)
{
    if (!dhtassoc || !cnd_entry || !index || !cl_entryptr)
        return 0;

    if (!clients_create_internal(dhtassoc, cnd_entry, index, cl_entryptr))
        return 0;

    /* setup the thing: overwrite what we can't keep from candidate
     * (everything that ends with _cl) */
    Client_entry *cl_entry = *cl_entryptr;
    cl_entry->used_cl = 0;
    cl_entry->bad_cl  = 0;

    return 1;
}

/* new empty entry except hash/id */
static uint8_t clients_create_new(DHT_assoc *dhtassoc, hash_t hash, uint8_t *id, size_t *index,
                                  Client_entry **targetptr)
{
    Client_entry source;
    memset(&source, 0, sizeof(source));
    source.hash = hash;
    id_copy(source.client.client_id, id);

    return clients_create_internal(dhtassoc, &source, index, targetptr);
}

static void clients_update_assoc(DHT_assoc *dhtassoc, Client_entry *entry, IP_Port *ipp, uint8_t seen)
{
    if (!dhtassoc || !entry || !ipp)
        return;

    if (!seen) {
        entry_heard_store(entry, ipp);
        return;
    }

    /* seen: IP_Port is reachable, without a doubt */
    IPPTsPng *assoc = entry_assoc(entry, ipp);

    if (!assoc)
        return;

    /* just overwrite and update timestamps */
    assoc->ip_port = *ipp;
    assoc->timestamp = unix_time();

    entry->seen_at = unix_time();
    entry->seen_family = ipp->ip.family;

    /* node is "good" again */
    entry->bad_cl = 0;
}

static void clients_update(DHT_assoc *dhtassoc, size_t index, IP_Port *ipp, uint8_t seen)
{
    if (index > dhtassoc->clients_fixed.capacity)
        return;

    Client_entry *entry = dhtassoc->clients_fixed.list[index - 1];

    if (!entry)
        return;

    clients_update_assoc(dhtassoc, entry, ipp, seen);
}

/* also frees the entry structure */
static void clients_destroy(DHT_assoc *dhtassoc, size_t index, Client_entry *entry)
{
    if (!dhtassoc || !entry)
        return;

    if (index > dhtassoc->clients_fixed.capacity)
        return;

    if (dhtassoc->clients_fixed.list[index - 1] != entry)
        return;

    /* sorted: find it */
    bucket_t sorted_bucket;
    size_t sorted_index;

    if (!clients_search(dhtassoc, entry->client.client_id, entry->hash, NULL, NULL, &sorted_bucket, &sorted_index))
        return;

    size_t num = dhtassoc->clients_sorted[sorted_bucket].num;

    if (num <= sorted_index)
        return;

    index_entry *ies = dhtassoc->clients_sorted[sorted_bucket].index_entry_list;

    if (ies[sorted_index].entry != entry)
        return;

    /* ok, all data gathered, complete operation */

    /* fixed: just kill */
    dhtassoc->clients_fixed.list[index - 1] = NULL;

    /* sorted: move sorted_index + 1 .. num - 1 to sorted_index .. num - 2 */
    size_t moves = num - (sorted_index + 1);

    if (moves > 0)
        memmove(&ies[sorted_index], &ies[sorted_index + 1], moves * sizeof(*ies));

    dhtassoc->clients_sorted[sorted_bucket].num--;
    free(entry);
}

static Client_entry *clients_get(DHT_assoc *dhtassoc, size_t index)
{
    if (!dhtassoc)
        return NULL;

    if (index > dhtassoc->clients_fixed.capacity)
        return NULL;

    return dhtassoc->clients_fixed.list[index - 1];
}

/*****************************************************************************/
/*                          CANDIDATES FUNCTIONS                             */
/*****************************************************************************/


static bucket_t candidates_id_bucket(uint8_t *id)
{
    return id_bucket(id, CANDIDATES_BUCKET_BITS);
}

static uint8_t candidates_search(DHT_assoc *dhtassoc, uint8_t *id, hash_t hash, Client_entry **entryptr)
{
    bucket_t bucket = candidates_id_bucket(id);
    candidates_bucket *cnd_bckt = &dhtassoc->candidates[bucket];
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

static void candidates_update_assoc(DHT_assoc *dhtassoc, Client_entry *entry, uint8_t seen, IP_Port *ipp)
{
    if (!dhtassoc || !entry || !ipp)
        return;

    IPPTsPng *assoc = entry_assoc(entry, ipp);

    if (!assoc)
        return;

    /* do NOT do anything related to wanted, that's handled outside,
     * just update the assoc (in the most sensible way)
     */
    if (seen) {
        assoc->ip_port = *ipp;
        assoc->timestamp = unix_time();

        entry->seen_at = unix_time();
        entry->seen_family = ipp->ip.family;

        return;
    }

    entry_heard_store(entry, ipp);
}

static uint8_t candidates_create_internal(DHT_assoc *dhtassoc, hash_t hash, uint8_t *id, uint8_t seen, uint8_t wanted,
        bucket_t *bucketptr, size_t *posptr)
{
    if (!dhtassoc || !id || !bucketptr ||  !posptr)
        return 0;

    bucket_t bucket = candidates_id_bucket(id);
    candidates_bucket *cnd_bckt = &dhtassoc->candidates[bucket];

    size_t coll, pos = hash % CANDIDATES_TO_KEEP, check;
    size_t pos_check[6];

    memset(pos_check, 0, sizeof(pos_check));

    for (coll = 0; coll < HASH_COLLIDE_COUNT; pos = hash_collide(pos) , coll++) {
        Client_entry *entry = &cnd_bckt->list[pos];

        if (!entry->hash) {
            *bucketptr = bucket;
            *posptr = pos;

            return 1;
        }

        /* 0. unwanted, fully bad
         * 1. unwanted, seen bad, heard good

         * 2. wanted, fully bad
         * 3. wanted, seen bad, heard good

         * 4. unwanted, seen good
         * 5. wanted, seen good */
        if (!is_timeout(entry->seen_at, CANDIDATES_SEEN_TIMEOUT))
            check = entry->wanted_at_cnd ? 5 : 4;
        else {
            check = entry->wanted_at_cnd ? 2 : 0;

            if (!is_timeout(entry->heard_at, CANDIDATES_HEARD_TIMEOUT))
                check += 1;
        }

        if (!pos_check[check])
            pos_check[check] = pos + 1;
    }

    /* if it's wanted, allow to bump anything but a good wanted node,
     * otherwise only bump bad or partially bad unwanted node
     */
    size_t i, pos_max = wanted ? 5 : 2;

    for (i = 0; i < pos_max; i++)
        if (pos_check[i]) {
            *bucketptr = bucket;
            *posptr = pos_check[i] - 1;

            return 1;
        }

    return 0;
}

static void candidates_create_new(DHT_assoc *dhtassoc, hash_t hash, uint8_t *id, uint8_t seen, uint8_t wanted,
                                  IP_Port *ipp)
{
    if (!dhtassoc || !id || !ipp)
        return;

    bucket_t bucket;
    size_t pos;

    if (!candidates_create_internal(dhtassoc, hash, id, seen, wanted, &bucket, &pos))
        return;

    candidates_bucket *cnd_bckt = &dhtassoc->candidates[bucket];
    Client_entry *entry = &cnd_bckt->list[pos];
    memset(entry, 0, sizeof(*entry));

    IPPTsPng *assoc = entry_assoc(entry, ipp);

    if (!assoc)
        return;

    entry->hash = hash;
    id_copy(entry->client.client_id, id);

    if (!entry->wanted_at_cnd && wanted) {
        entry->wanted_at_cnd = unix_time();
        entry->wanted_req_cnd = 0;
    }

    if (seen) {
        entry->seen_at = unix_time();
        entry->seen_family = ipp->ip.family;

        assoc->ip_port = *ipp;
        assoc->timestamp = unix_time();
    } else {
        IP_Port *heard = entry_heard_get(entry, ipp);

        if (heard) {
            entry->heard_at = unix_time();
            entry->heard_family = ipp->ip.family;
            *heard = *ipp;
        }
    }
}

static void candidates_create_from_clients(DHT_assoc *dhtassoc, Client_entry *source)
{
    if (!dhtassoc || !source)
        return;

    uint8_t seen = !is_timeout(source->seen_at, CANDIDATES_SEEN_TIMEOUT);
    bucket_t bucket;
    size_t pos;

    if (!candidates_create_internal(dhtassoc, source->hash, source->client.client_id, seen, 0, &bucket, &pos))
        return;

    candidates_bucket *cnd_bckt = &dhtassoc->candidates[bucket];
    Client_entry *entry = &cnd_bckt->list[pos];
    memcpy(entry, source, sizeof(*entry));

    /* reset all union fields (end with _cnd) */
    entry->wanted_at_cnd  = 0;
    entry->wanted_req_cnd = 0;
}


/*****************************************************************************/
/*                            TRIGGER FUNCTIONS                              */
/*****************************************************************************/

/* Central entry point for new associations: add a new candidate to the cache
 * seen should be 0 (zero), if the candidate was announced by someone else,
 * seen should be 1 (one), if there is confirmed connectivity (a definite response)
 */
void DHT_assoc_candidate_new(DHT_assoc *dhtassoc, uint8_t *id, IP_Port *ipp, uint8_t seen)
{
    if (!dhtassoc || !id || !ipp)
        return;

    if (!ipport_isset(ipp))
        return;

    hash_t hash = id_hash(id);

    if (hash == dhtassoc->self_hash)
        if (id_equal(id, dhtassoc->self_client_id))
            return;

    /* if it's new:
     * callback, if there's desire, add to clients, else to candidates
     *
     * if it's "old":
     *    if it's client: refresh
     *    if it's candidate:
     *       if !seen, refresh
     *       if seen: callback, if there's desire, move to candidates
     */
    Client_entry *cl_entry;
    size_t index;

    if (clients_search(dhtassoc, id, hash, &index, &cl_entry, NULL, NULL)) {
        clients_update(dhtassoc, index, ipp, seen);
        return;
    }

    Client_entry *cnd_entry;

    if (candidates_search(dhtassoc, id, hash, &cnd_entry)) {
        if (!seen) {
            candidates_update_assoc(dhtassoc, cnd_entry, seen, ipp);

            return;
        }

        if (!cnd_entry->seen_at && cnd_entry->wanted_at_cnd) {
            /* first time seen since wanted */
            if (clients_create_from_candidates(dhtassoc, cnd_entry, &index, &cl_entry)) {
                clients_update_assoc(dhtassoc, cl_entry, ipp, seen);
                clients_update_usable(dhtassoc, index, cl_entry);

                if (cl_entry->used_cl) {
                    /* "remove" from candidates */
                    cnd_entry->hash = 0;
                    return;
                }

                /* money for nothing... */
                clients_destroy(dhtassoc, index, cl_entry);
                cnd_entry->wanted_at_cnd = 0;
                cnd_entry->wanted_req_cnd = 0;
            }
        }

        candidates_update_assoc(dhtassoc, cnd_entry, seen, ipp);

        return;
    }

    /* looks new: check for desire */
    uint32_t wanted = handlers_entry_wanted(dhtassoc, hash, id, seen, ipp);

    if (!wanted) {
        candidates_create_new(dhtassoc, hash, id, seen, wanted, ipp);

        return;
    }

    /* there is desire */
    if (seen) {
        if (clients_create_new(dhtassoc, hash, id, &index, &cl_entry))
            clients_update_usable(dhtassoc, index, cl_entry);

        return;
    } else {
        candidates_create_new(dhtassoc, hash, id, seen, wanted, ipp);

        return;
    }
}

/* Drop a "used" flag by one. To be called when a function kicks an entry out of
 * their specific "CLOSE" list for anything.
 */
void DHT_assoc_client_drop(DHT_assoc *dhtassoc, size_t index)
{
    Client_entry *entry = clients_get(dhtassoc, index);

    if (!entry)
        return;

    /* guard against underflow */
    usecnt_t used = entry->used_cl;

    if (entry->used_cl)
        entry->used_cl--;

    if (!entry->used_cl) {
        /* maybe the accounting was screwed up... recount */
        clients_update_usage(dhtassoc, index, entry);

        if (!entry->used_cl) {
            /* again: protect against issues with accounting */
            if (used)
                handlers_entry_deleting(dhtassoc, index, entry);

            /* (maybe) move to candidates & kill it */
            candidates_create_from_clients(dhtassoc, entry);
            clients_destroy(dhtassoc, index, entry);
        }
    }
}

/*****************************************************************************/
/*                   OUTSIDE FULL HANDLER FUNCTIONS                          */
/*****************************************************************************/

uint8_t DHT_assoc_close_nodes_find(DHT_assoc *dhtassoc, uint8_t *id, DHT_assoc_close_nodes_simple *state)
{
    if (!dhtassoc || !id || !state || !state->close_indices)
        return 0;


    if (!state->distance_relative_func)
        state->distance_relative_func = assoc_id_closest;

    if (!state->distance_absolute_func)
        state->distance_absolute_func = id_distance;

    size_t clients_offset = CANDIDATES_BUCKET_COUNT * CANDIDATES_TO_KEEP;
    size_t dist_list_len = clients_offset + dhtassoc->clients_fixed.capacity;
    uint64_t dist_list[dist_list_len];
    memset(dist_list, ~0, dist_list_len * sizeof(dist_list[0]));
    bucket_t b;
    size_t i;

    for (b = 0; b < CANDIDATES_BUCKET_COUNT; b++) {
        candidates_bucket *cnd_bckt = &dhtassoc->candidates[b];

        for (i = 0; i < CANDIDATES_TO_KEEP; i++) {
            Client_entry *entry = &cnd_bckt->list[i];

            if (entry->hash) {
                uint64_t dist = state->distance_absolute_func(dhtassoc, state->custom_data, id, entry->client.client_id);
                uint32_t index = b * CANDIDATES_TO_KEEP + i;
                dist_list[index] = (dist << DISTANCE_INDEX_INDEX_BITS) | index;
            }
        }
    }

    size_t clients_num = 0;

    for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
        Client_entry *entry = dhtassoc->clients_fixed.list[i];

        if (entry) {
            uint64_t dist = state->distance_absolute_func(dhtassoc, state->custom_data, id, entry->client.client_id);
            uint32_t index = clients_offset + i;
            dist_list[index] = (dist << DISTANCE_INDEX_INDEX_BITS) | index;
            clients_num++;
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
                dist_index_bubble(dhtassoc, dist_list, ind_prev, ind_curr - 1, id, state->custom_data, state->distance_relative_func);

            dist_prev = dist_curr;
            ind_prev = ind_curr;
            len = 1;
        }
    }

    if (len > 1)
        dist_index_bubble(dhtassoc, dist_list, ind_prev, ind_curr - 1, id, state->custom_data, state->distance_relative_func);

    /* ok, now dist_list is a strictly ascending sorted list of nodes
     * a) extract CLOSE_QUOTA_USED clients, not timed out
     * b) extract (1 - QUOTA) (better!) clients & candidates, not timed out
     * c) save candidates which would be better, if contact can be established */
    size_t client_quota_curr = 0, pos = 0, wanted = 0;
    size_t client_quota_max = CLOSE_QUOTA_USED * state->close_count;

    ssize_t taken_last = - 1;

    for (i = 0; (i < dist_list_len) && (pos < state->close_count); i++) {
        uint32_t ind = dist_list[i] & DISTANCE_INDEX_INDEX_MASK;

        if ((ind >= clients_offset) || (client_quota_curr >= client_quota_max)) {
            Client_entry *entry = dist_index_entry(dhtassoc, dist_list[i]);

            if (entry) {
                if (!is_timeout(entry->seen_at, BAD_NODE_TIMEOUT)) {
                    if (ind < clients_offset) {
                        size_t cl_ind;
                        Client_entry *cl_entry;

                        if (clients_create_from_candidates(dhtassoc, entry, &cl_ind, &cl_entry)) {
                            taken_last = i;
                            entry->used_cl++;
                            state->close_indices[pos++] = cl_ind;
                            continue;
                        }
                    } else {
                        taken_last = i;
                        state->close_indices[pos++] = ind - clients_offset;
                        client_quota_curr++;
                        continue;
                    }
                }
            }
        }

        if (pos + wanted < state->close_count) {
            Client_entry *entry = dist_index_entry(dhtassoc, dist_list[i]);

            if (entry && (entry->seen_at || entry->heard_at))
                if (!entry->wanted_at_cnd) {
                    entry->wanted_at_cnd = unix_time();
                    entry->wanted_req_cnd = 0;
                    wanted++;

                    if (dhtassoc->dht) {
                        IP_Port *ipp = entry_ipport_get(entry, 0);

                        if (ipp) {
                            add_toping(dhtassoc->dht->ping, entry->client.client_id, *ipp);
                            DHT_request_nodes(dhtassoc->dht, entry->client.client_id, ipp, id);
                        }
                    }
                }
        }
    }

    /* if we had not enough clients to open us up to candidates,
     * the list might still not be filled.
     *
     * start again from last taken client, but leave out the
     * QUOTA requirement
     */
    if (pos < state->close_count) {
        for (i = taken_last + 1; (i < dist_list_len) && (pos < state->close_count); i++) {
            uint32_t ind = dist_list[i] & DISTANCE_INDEX_INDEX_MASK;
            Client_entry *entry = dist_index_entry(dhtassoc, dist_list[i]);

            if (entry) {
                if (!is_timeout(entry->seen_at, BAD_NODE_TIMEOUT)) {
                    if (ind < clients_offset) {
                        size_t cl_ind;
                        Client_entry *cl_entry;

                        if (clients_create_from_candidates(dhtassoc, entry, &cl_ind, &cl_entry)) {
                            taken_last = i;
                            entry->used_cl++;
                            state->close_indices[pos++] = cl_ind;
                            continue;
                        }
                    } else {
                        taken_last = i;
                        state->close_indices[pos++] = ind - clients_offset;
                        client_quota_curr++;
                        continue;
                    }
                }
            }
        }
    }

    return pos;
}

/*****************************************************************************/
/*                        REGISTERING FUNCTIONS                              */
/*****************************************************************************/

/* Register callback functions */
void DHT_assoc_register_callback(DHT_assoc *dhtassoc, char *description, void *callback_data,
                                 DHT_assoc_callbacks *callback_funcs)
{
    if (!dhtassoc || !callback_funcs)
        return;

    size_t i, empty = 0;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler) {
            if (!empty)
                empty = i + 1;

            continue;
        }

        if (handler->data_cb == callback_data) {
            handler->description = description;
            handler->callbacks = callback_funcs;
            return;
        }
    }

    Handler *handler = calloc(1, sizeof(*handler));

    if (!handler)
        return;

    if (empty)
        empty--;
    else {
        /* must allocate more space */
        size_t capacity_old = dhtassoc->handlers.capacity;
        size_t capacity_new = capacity_old + 32;
        Handler **handlers = realloc(dhtassoc->handlers.list, capacity_new * sizeof(Handler *));

        if (!handlers) {
            free(handler);
            return;
        }

        memset(&handlers[capacity_old], 0, (capacity_new - capacity_old) * sizeof(Handler *));
        dhtassoc->handlers.list = handlers;
        dhtassoc->handlers.capacity = capacity_new;

        empty = capacity_old;
    }

    handler->description = description;
    handler->data_cb = callback_data;
    handler->callbacks = callback_funcs;
    handler->dist_rel_func = handler->callbacks->distance_relative_func;

    if (!handler->dist_rel_func)
        handler->dist_rel_func = assoc_id_closest;

    dhtassoc->handlers.list[empty] = handler;
}

/* Unregister callback functions */
void DHT_assoc_unregister_callback(DHT_assoc *dhtassoc, void *callback_data, DHT_assoc_callbacks *callback_funcs)
{
    if (!dhtassoc || !callback_data || !callback_funcs)
        return;

    size_t i;

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (!handler)
            continue;

        if (handler->data_cb == callback_data) {
            dhtassoc->handlers.list[i] = NULL;
            free(handler);
            return;
        }
    }
}

/*****************************************************************************/
/*                     GLOBAL STRUCTURE FUNCTIONS                            */
/*****************************************************************************/

/* create */
DHT_assoc *DHT_assoc_new(DHT *dht)
{
    DHT_assoc *dhtassoc = calloc(1, sizeof(*dhtassoc));

    if (!dhtassoc)
        return NULL;

    /* dht MAY be NULL! (e.g. testing) */
    dhtassoc->dht = dht;

#ifdef DHT_ASSOC_HANDLER_FULL_DONE
    /* TODO: register self as handler */
#endif

    return dhtassoc;
}

/* own client_id, assocs for this have to be ignored */
void DHT_assoc_self(DHT_assoc *dhtassoc, uint8_t *client_id)
{
    if (dhtassoc) {
        dhtassoc->self_hash = id_hash(client_id);
        id_copy(dhtassoc->self_client_id, client_id);

        /* TODO: if we already added some (or loaded some) entries,
         * look and remove if we find a match
         */
        size_t i;

        for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
            Client_entry *entry = dhtassoc->clients_fixed.list[i];

            if (entry)
                if (dhtassoc->self_hash == entry->hash)
                    if (id_equal(dhtassoc->self_client_id, entry->client.client_id)) {
                        if (entry->used_cl)
                            handlers_entry_deleting(dhtassoc, i + 1, entry);

                        /* check if the entry has been dropped */
                        entry = dhtassoc->clients_fixed.list[i];

                        if (entry)
                            clients_destroy(dhtassoc, i + 1, entry);

                        break;
                    }
        }

        bucket_t b_id = candidates_id_bucket(client_id);
        candidates_bucket *cnd_bckt = &dhtassoc->candidates[b_id];
        size_t pos = dhtassoc->self_hash % CANDIDATES_TO_KEEP;

        for (i = 0; i < HASH_COLLIDE_COUNT; pos = hash_collide(pos), i++) {
            Client_entry *entry = &cnd_bckt->list[pos];

            if (entry->hash == dhtassoc->self_hash)
                if (id_equal(entry->client.client_id, dhtassoc->self_client_id)) {
                    entry->hash = 0;
                    break;
                }

        }
    }
}

/* worker */
void DHT_assoc_do(DHT_assoc *dhtassoc)
{
    if (!dhtassoc)
        return;

    if (dhtassoc->dht && is_timeout(dhtassoc->worker_do.wanted, 0)) {
        uint64_t wanted_again = unix_time();
        size_t b_ix, b_id;

        for (b_ix = 0; b_ix < CANDIDATES_BUCKET_COUNT; b_ix++) {
            candidates_bucket *cnd_bckt = &dhtassoc->candidates[b_ix];

            for (b_id = 0; b_id < CANDIDATES_TO_KEEP; b_id++) {
                Client_entry *entry = &cnd_bckt->list[b_id];

                if (entry->hash && entry->wanted_at_cnd) {
                    if (is_timeout(entry->wanted_at_cnd, (entry->wanted_req_cnd + 1) * BAD_NODE_TIMEOUT / 3)) {
                        entry->wanted_req_cnd++;

                        if (dhtassoc->dht) {
                            /* use the youngest entry */
                            IP_Port *ipp = entry_ipport_get(entry, 1);

                            if (ipp)
                                add_toping(dhtassoc->dht->ping, entry->client.client_id, *ipp);
                        }
                    } else
                        wanted_again = min_u64(wanted_again, entry->wanted_at_cnd + entry->wanted_req_cnd * BAD_NODE_TIMEOUT / 3);
                }
            }
        }

        dhtassoc->worker_do.wanted = wanted_again + BAD_NODE_TIMEOUT / 3;
    }

    if (is_timeout(dhtassoc->worker_do.bad, 0)) {
        /* check clients for timeouts */
        size_t i, h;
        uint64_t bad_again = unix_time();

        for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
            Client_entry *entry = dhtassoc->clients_fixed.list[i];

            if (!entry)
                continue;

            if (entry->used_cl && is_timeout(entry->seen_at, BAD_NODE_TIMEOUT)) {
                if (!entry->bad_cl) {
                    entry->bad_cl = 1;

                    for (h = 0; h < dhtassoc->handlers.capacity; h++) {
                        Handler *handler = dhtassoc->handlers.list[h];

                        if (handler) {
                            DHT_assoc_check_bad_callback check_bad_func = handler->callbacks->check_funcs.check_bad_func;

                            if (check_bad_func)
                                check_bad_func(dhtassoc, handler->data_cb, i + 1, &entry->client);
                        }
                    }

                    /* check if the entry has been dropped */
                    Client_entry *entry = dhtassoc->clients_fixed.list[i];

                    if (!entry)
                        continue;

                    /* not dropped, but maybe noone had it anyways? recheck usage */
                    clients_update_usage(dhtassoc, i + 1, entry);

                    /* if unused, can move out */
                    if (!entry->used_cl) {
                        candidates_create_from_clients(dhtassoc, entry);
                        clients_destroy(dhtassoc, i + 1, entry);
                    }
                }
            }

            if (!is_timeout(entry->seen_at, BAD_NODE_TIMEOUT))
                bad_again = min_u64(bad_again, entry->seen_at);
        }


        dhtassoc->worker_do.bad = bad_again + BAD_NODE_TIMEOUT;
    }

    if (is_timeout(dhtassoc->worker_do.kill, 0)) {
        /* check clients for timeouts */
        size_t i;
        uint64_t kill_again = unix_time();

        for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
            Client_entry *entry = dhtassoc->clients_fixed.list[i];

            if (!entry)
                continue;

            if (is_timeout(entry->seen_at, KILL_NODE_TIMEOUT)) {
                if (entry->used_cl)
                    handlers_entry_deleting(dhtassoc, i + 1, entry);

                /* check if the entry has been dropped */
                Client_entry *entry = dhtassoc->clients_fixed.list[i];

                if (!entry)
                    continue;

                candidates_create_from_clients(dhtassoc, entry);
                clients_destroy(dhtassoc, i + 1, entry);
            } else
                kill_again = min_u64(kill_again, entry->seen_at);
        }


        dhtassoc->worker_do.kill = kill_again + KILL_NODE_TIMEOUT;
    }

#ifdef DHT_ASSOC_HANDLER_FULL_DONE
    /* TODO: a lot more */
#endif
}

/* destroy */
void DHT_assoc_kill(DHT_assoc *dhtassoc)
{
    /* free all suballocations: basically just the clients lists */
    size_t i;

    for (i = 0; i < dhtassoc->clients_fixed.capacity; i++) {
        Client_entry *entry = dhtassoc->clients_fixed.list[i];

        if (entry) {
            free(entry);
            dhtassoc->clients_fixed.list[i] = NULL;
        }
    }

    for (i = 0; i < CLIENTS_BUCKET_COUNT; i++) {
        index_entry *ies = dhtassoc->clients_sorted[i].index_entry_list;

        if (ies) {
            free(ies);
            dhtassoc->clients_sorted[i].index_entry_list = NULL;
            dhtassoc->clients_sorted[i].capacity = 0;
            dhtassoc->clients_sorted[i].num = 0;
        }
    }

    for (i = 0; i < dhtassoc->handlers.capacity; i++) {
        Handler *handler = dhtassoc->handlers.list[i];

        if (handler) {
            free(handler);
            dhtassoc->handlers.list[i] = NULL;
        }
    }

    free(dhtassoc->handlers.list);
    dhtassoc->handlers.list = NULL;
    dhtassoc->handlers.capacity = 0;

    free(dhtassoc);
}

/*****************************************************************************/

/* Access the used client_list */
Client_data *DHT_assoc_client(DHT_assoc *dhtassoc, size_t index)
{
    if (!dhtassoc)
        return NULL;

    /* not >= ! */
    if (index > dhtassoc->clients_fixed.capacity)
        return NULL;

    Client_entry *entry = dhtassoc->clients_fixed.list[index - 1];

    if (!entry)
        return NULL;

    return &entry->client;
}

/*****************************************************************************/

void DHT_assoc_calc_statistics(DHT_assoc *dhtassoc, DHT_assoc_statistics *assoc_stat)
{
    if (!dhtassoc || !assoc_stat)
        return;

    memset(assoc_stat, 0, sizeof(*assoc_stat));

    bucket_t b_id;
    size_t b_ix;

    for (b_id = 0; b_id < CANDIDATES_BUCKET_COUNT; b_id++) {
        candidates_bucket *bucket = &dhtassoc->candidates[b_id];

        for (b_ix = 0; b_ix < CANDIDATES_TO_KEEP; b_ix++)
            if (bucket->list[b_ix].hash)
                assoc_stat->candidates++;
    }

    size_t i;

    for (i = 0; i < dhtassoc->clients_fixed.capacity; i++)
        if (dhtassoc->clients_fixed.list[i])
            assoc_stat->clients++;

    for (i = 0; i < dhtassoc->handlers.capacity; i++)
        if (dhtassoc->handlers.list[i])
            assoc_stat->handlers++;
}


uint8_t DHT_assoc_testing_search_helper(uint16_t hash, uint16_t *hashes, uint16_t hashes_len, uint16_t *first,
                                        uint16_t *last)
{
    index_entry iel[hashes_len];
    Client_entry entries[hashes_len];

    size_t i;

    for (i = 0; i < hashes_len; i++) {
        iel[i].fixed = i;
        iel[i].entry = &entries[i];
        entries[i].hash = hashes[i];
    }

    size_t _first, _last;
    uint8_t res = clients_search_helper(hash, hashes_len, iel, &_first, &_last);

    if (res) {
        *first = _first;
        *last = _last;
    }

    return res;
}
