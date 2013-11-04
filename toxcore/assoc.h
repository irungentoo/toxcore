
#ifndef __DHT_ASSOC_H__
#define __DHT_ASSOC_H__

/* For the legalese parts, see tox.h. */

/*
 * Module to handle the ID <=> IP association on a more global level.
 * Avoids duplicate code and allows to move forward towards a
 * sendpacket(..., ID, packet, ...), centralizing the choice of
 * transport in the DHT.
 */

typedef struct IP_Port IP_Port;
typedef struct DHT_assoc DHT_assoc;

/*****************************************************************************/

/* custom distance handler, if it's not ID-distance based
 * return values exactly like id_closest() */
typedef int (*DHT_assoc_distance_relative_callback)(DHT_assoc *dhtassoc, void *callback_data, uint8_t *client_id,
        uint8_t *client_id1, uint8_t *client_id2);

#define DISTANCE_INDEX_DISTANCE_BITS 44

/* absolute distance: can be same for different client_id_check values
 * return value should have DISTANCE_INDEX_DISTANCE_BITS valid bits */
typedef uint64_t (*DHT_assoc_distance_absolute_callback)(DHT_assoc *dhtassoc, void *callback_data,
        uint8_t *client_id_ref, uint8_t *client_id_check);

/*****************************************************************************/

/* callbacks: checking for interest in new/updated candidate, notifying of to be deleted candidate
 * - new   : returning 1 means interested
 * - usable: returning number of ADDITIONAL usage
 * - usage : returning number of TOTAL usage
 * - bad   : returning number of REMOVED usage
 * - delete: no return code
 */
/* new association discovered             : returning 1 means "interested" */
typedef uint8_t (*DHT_assoc_check_new_callback)(DHT_assoc *dhtassoc, void *callback_data, uint32_t hash,
        uint8_t *client_id, uint8_t seen, IP_Port *ipp);
/* association added/moved to clients     : returning number of ADDITIONAL usage */
typedef uint16_t (*DHT_assoc_check_usable_callback)(DHT_assoc *dhtassoc, void *callback_data, uint32_t client_pos,
        Client_data *client);
/* re-checking usage counters             : returning number of TOTAL usage */
typedef uint16_t (*DHT_assoc_check_usage_callback)(DHT_assoc *dhtassoc, void *callback_data, uint32_t client_pos,
        Client_data *client);
/* node has gone "bad" (BAD_NODE_TIMEOUT) : no rc, assuming that DHT_assoc_ candidate_drop() is called */
typedef void (*DHT_assoc_check_bad_callback)(DHT_assoc *dhtassoc, void *callback_data, uint32_t client_pos,
        Client_data *client);
/* node is going to move out from clients : no rc, just a notification */
typedef void (*DHT_assoc_check_delete_callback)(DHT_assoc *dhtassoc, void *callback_data, uint32_t client_pos,
        Client_data *client);

typedef struct DHT_assoc_check_callbacks {
    DHT_assoc_check_new_callback    check_new_func;
    DHT_assoc_check_usable_callback check_usable_func;
    DHT_assoc_check_usage_callback  check_usage_func;
    DHT_assoc_check_bad_callback    check_bad_func;
    DHT_assoc_check_delete_callback check_delete_func;
} DHT_assoc_check_callbacks;

/*****************************************************************************/

typedef struct DHT_assoc_callbacks {
    DHT_assoc_distance_relative_callback  distance_relative_func;
    DHT_assoc_distance_absolute_callback  distance_absolute_func;
    DHT_assoc_check_callbacks             check_funcs;
} DHT_assoc_callbacks;

DHT_assoc_callbacks *DHT_assoc_callbacks_default();

/*****************************************************************************/

/* Central entry point for new associations: add a new candidate to the cache
 * seen should be 0 (zero), if the candidate was announced by someone else,
 * seen should be 1 (one), if there is confirmed connectivity (a definite response)
 */
void DHT_assoc_candidate_new(DHT_assoc *dhtassoc, uint8_t *id, IP_Port *ipp, uint8_t seen);

/* Drop a "used" flag by one. To be called when a function kicks an entry out of
 * their specific "CLOSE" list for anything.
 */
void DHT_assoc_client_drop(DHT_assoc *dhtassoc, size_t index);

/*****************************************************************************/

typedef struct DHT_assoc_close_nodes_simple {
    void                                  *custom_data; /* given to distance functions */
    DHT_assoc_distance_relative_callback   distance_relative_func;
    DHT_assoc_distance_absolute_callback   distance_absolute_func;

    uint8_t                                close_count;
    size_t                                *close_indices;
} DHT_assoc_close_nodes_simple;

/* find up to close_count nodes to put into close_nodes_used of ID_Nodes
 * the distance functions can be NULL, then standard distance functions will be used
 * the caller is responsible for allocating close_indices of sufficient size
 *
 * returns 0 on error
 * returns the number of found nodes and the list of indices usable by DHT_assoc_client()
 *    the caller is assumed to be registered from DHT_assoc_register_callback()
 *    if they aren't, they should copy the Client_data and call DHT_assoc_client_drop()
 */
uint8_t DHT_assoc_close_nodes_find(DHT_assoc *dhtassoc, uint8_t *id, DHT_assoc_close_nodes_simple *close_nodes_simple);

/*****************************************************************************/

#ifdef DHT_ASSOC_RECHECK_DONE

/* Initiate candidate recheck for a specific function:
 * If we got a new friend/group/peer/..., we want to recheck all candidates if there is
 * any "CLOSE" to THAT by the specific distance function.
 * The function will throw all the candidates, and the callback shall mark which ones it
 * "wants" (wanted) / "keeps" (used).
 */
void DHT_assoc_candidate_recheck_specific(DHT_assoc *dhtassoc, void *callback_data,
        DHT_assoc_check_callbacks callback_funcs);

/* Reset total client_list_use_count and call the callbacks to recount the current use.
 * Should be called rarely, if ever.
 */
void DHT_assoc_candidate_recheck_global(DHT_assoc *dhtassoc);

#endif

/*****************************************************************************/

/* Register callback functions
 * description may be NULL
 * callback_data mustn't be NULL, as it "identifies" the handler */
void DHT_assoc_register_callback(DHT_assoc *dhtassoc, char *description, void *callback_data,
                                 DHT_assoc_callbacks *callback_funcs);

/* Unregister callback functions */
void DHT_assoc_unregister_callback(DHT_assoc *dhtassoc, void *callback_data, DHT_assoc_callbacks *callback_funcs);

/*****************************************************************************/

/* create */
DHT_assoc *DHT_assoc_new(DHT *dht);

/* set own client_id, anything with that is discarded
 *
 * cannot demand on creation, because it might have to be loaded
 * from disk yet */
void DHT_assoc_self(DHT_assoc *dhtassoc, uint8_t *client_id);

/* worker */
void DHT_assoc_do(DHT_assoc *dhtassoc);

/* destroy */
void DHT_assoc_kill(DHT_assoc *dhtassoc);

/*****************************************************************************/

#ifdef DHT_ASSOC_HANDLER_FULL_DONE
/* handler:
 *
 * DHT_assoc handles the complete work of keeping the X_CLOSE ID<=>assoc lists of a number of X IDs
 * with a "user"-defined distance function
 *
 * add/delete a handler
 *
 * description;                 : if not NULL, a description (for logging/debugging/etc.)
 * callback_data;               : opaque outside something
 * close_count                  : number of close nodes
 * callbacks                    : callbacks, missing functions will be replaced by defaults
 *
 * returns a cookie value for ok, 0 for error
 */
uint32_t DHT_assoc_handler_new(DHT_assoc *dhtassoc, char *description, void *callback_data, size_t close_count,
                               DHT_assoc_callbacks *callbacks);
uint32_t DHT_assoc_handler_delete(DHT_assoc *dhtassoc, uint32_t cookie);

/* adds/removes an entry
 *
 * returns (index + 1) when successful, 0 on error */
uint32_t DHT_assoc_handler_entry_add(DHT_assoc *dhtassoc, uint32_t cookie, uint8_t *id);
uint32_t DHT_assoc_handler_entry_delete(DHT_assoc *dhtassoc, uint32_t cookie, uint8_t *id);

/* Access the used client_list of a handler's group element at index index
 * index is greater zero for regular entries
 * if index equals zero, a random valid node is picked
 * flags can be a combination of:
 *   1: ignore timeout
 *
 * returns
 *     NULL if the index is invalid/timed-out / there are no valid/not timed-out entries
 *     index >  0: the Client_data of that index, if it is valid and, depending on flags, not timed out
 *     index == 0: the Client_data of a random valid and, depending on flags, not timed out index
 */
Client_data *DHT_assoc_group_client(DHT_assoc *dhtassoc, uint32_t cookie, size_t group_index, size_t close_index, uint8_t flags);
#endif

/*****************************************************************************/

/* Access the used client_list: Transient function. */
Client_data *DHT_assoc_client(DHT_assoc *dhtassoc, size_t index);

/* Retrieve the necessary contact data for a client.
 * Flags indicate additional restrictions like timeouts (n.y.i.).
 *
 *  returns 0 on error
 *  returns 1 and valid pointers on success.
 */
int DHT_assoc_client_ip(DHT_assoc *dhtassoc, size_t index, uint8_t flags, uint8_t *client_id, IP_Port **ipp);

/*****************************************************************************/

typedef struct DHT_assoc_statistics {
    size_t clients, candidates, handlers;
} DHT_assoc_statistics;

void DHT_assoc_calc_statistics(DHT_assoc *dhtassoc, DHT_assoc_statistics *assoc_stat);

/*****************************************************************************/

/* testing special, too many internal structures required to move it to test */

uint8_t DHT_assoc_testing_search_helper(uint16_t hash, uint16_t *hashes, uint16_t hashes_len, uint16_t *first,
                                        uint16_t *last)
#ifndef AUTO_TEST
__attribute__((__deprecated__))
#endif
; /* end of definition DHT_assoc_testing_search_helper() */

#endif /* !__DHT_ASSOC_H__ */
