/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/** @file
 * @brief An implementation of the DHT as seen in docs/updates/DHT.md
 */
#ifndef C_TOXCORE_TOXCORE_DHT_H
#define C_TOXCORE_TOXCORE_DHT_H

#include <stdbool.h>

#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "network.h"
#include "ping_array.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum size of a signature (may be smaller) */
#define SIGNATURE_SIZE CRYPTO_SIGNATURE_SIZE
/** Maximum number of clients stored per friend. */
#define MAX_FRIEND_CLIENTS 8

#define LCLIENT_NODES MAX_FRIEND_CLIENTS
#define LCLIENT_LENGTH 128

/** A list of the clients mathematically closest to ours. */
#define LCLIENT_LIST (LCLIENT_LENGTH * LCLIENT_NODES)

#define MAX_CLOSE_TO_BOOTSTRAP_NODES 8

/** The max number of nodes to send with send nodes. */
#define MAX_SENT_NODES 4

/** Ping timeout in seconds */
#define PING_TIMEOUT 5

/** size of DHT ping arrays. */
#define DHT_PING_ARRAY_SIZE 512

/** Ping interval in seconds for each node in our lists. */
#define PING_INTERVAL 60

/** The number of seconds for a non responsive node to become bad. */
#define PINGS_MISSED_NODE_GOES_BAD 1
#define PING_ROUNDTRIP 2
#define BAD_NODE_TIMEOUT (PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD * (PING_INTERVAL + PING_ROUNDTRIP))

/**
 * The number of "fake" friends to add.
 *
 * (for optimization purposes and so our paths for the onion part are more random)
 */
#define DHT_FAKE_FRIEND_NUMBER 2

/** Maximum packet size for a DHT request packet. */
#define MAX_CRYPTO_REQUEST_SIZE 1024

#define CRYPTO_PACKET_FRIEND_REQ    32  // Friend request crypto packet ID.
#define CRYPTO_PACKET_DHTPK         156
#define CRYPTO_PACKET_NAT_PING      254 // NAT ping crypto packet ID.

/* Max size of a packed node for IPV4 and IPV6 respectively */
#define PACKED_NODE_SIZE_IP4 (1 + SIZE_IP4 + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE)
#define PACKED_NODE_SIZE_IP6 (1 + SIZE_IP6 + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE)

/**
 * This define can eventually be removed; it is necessary if a significant
 * proportion of dht nodes do not implement the dht announcements protocol.
 */
#define CHECK_ANNOUNCE_NODE

/**
 * @brief Create a request to peer.
 *
 * Packs the data and sender public key and encrypts the packet.
 *
 * @param[in] send_public_key public key of the sender.
 * @param[in] send_secret_key secret key of the sender.
 * @param[out] packet an array of @ref MAX_CRYPTO_REQUEST_SIZE big.
 * @param[in] recv_public_key public key of the receiver.
 * @param[in] data represents the data we send with the request.
 * @param[in] data_length the length of the data.
 * @param[in] request_id the id of the request (32 = friend request, 254 = ping request).
 *
 * @attention Constraints:
 * @code
 * sizeof(packet) >= MAX_CRYPTO_REQUEST_SIZE
 * @endcode
 *
 * @retval -1 on failure.
 * @return the length of the created packet on success.
 */
non_null()
int create_request(const Random *rng, const uint8_t *send_public_key, const uint8_t *send_secret_key,
                   uint8_t *packet, const uint8_t *recv_public_key,
                   const uint8_t *data, uint32_t data_length, uint8_t request_id);

/**
 * @brief Decrypts and unpacks a DHT request packet.
 *
 * Puts the senders public key in the request in @p public_key, the data from
 * the request in @p data.
 *
 * @param[in] self_public_key public key of the receiver (us).
 * @param[in] self_secret_key secret key of the receiver (us).
 * @param[out] public_key public key of the sender, copied from the input packet.
 * @param[out] data decrypted request data, copied from the input packet, must
 *   have room for @ref MAX_CRYPTO_REQUEST_SIZE bytes.
 * @param[in] packet is the request packet.
 * @param[in] packet_length length of the packet.
 *
 * @attention Constraints:
 * @code
 * sizeof(data) >= MAX_CRYPTO_REQUEST_SIZE
 * @endcode
 *
 * @retval -1 if not valid request.
 * @return the length of the unpacked data.
 */
non_null()
int handle_request(
    const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
    uint8_t *request_id, const uint8_t *packet, uint16_t packet_length);

typedef struct IPPTs {
    IP_Port     ip_port;
    uint64_t    timestamp;
} IPPTs;

typedef struct IPPTsPng {
    IP_Port     ip_port;
    uint64_t    timestamp;
    uint64_t    last_pinged;

    /* Returned by this node */
    IP_Port     ret_ip_port;
    uint64_t    ret_timestamp;
    /* true if this ip_port is ours */
    bool        ret_ip_self;
} IPPTsPng;

typedef struct Client_data {
    uint8_t     public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IPPTsPng    assoc4;
    IPPTsPng    assoc6;

#ifdef CHECK_ANNOUNCE_NODE
    /* Responded to data search? */
    bool        announce_node;
#endif
} Client_data;

/*----------------------------------------------------------------------------------*/

typedef struct NAT {
    /* true if currently hole punching */
    bool        hole_punching;
    uint32_t    punching_index;
    uint32_t    tries;
    uint32_t    punching_index2;

    uint64_t    punching_timestamp;
    uint64_t    recv_nat_ping_timestamp;
    uint64_t    nat_ping_id;
    uint64_t    nat_ping_timestamp;
} NAT;

#define DHT_FRIEND_MAX_LOCKS 32

typedef struct Node_format {
    uint8_t     public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port     ip_port;
} Node_format;

extern const Node_format empty_node_format;

typedef struct DHT_Friend DHT_Friend;

non_null() const uint8_t *dht_friend_public_key(const DHT_Friend *dht_friend);
non_null() const Client_data *dht_friend_client(const DHT_Friend *dht_friend, size_t index);

/** @return packet size of packed node with ip_family on success.
 * @retval -1 on failure.
 */
int packed_node_size(Family ip_family);

/** @brief Pack an IP_Port structure into data of max size length.
 *
 * Packed_length is the offset of data currently packed.
 *
 * @return size of packed IP_Port data on success.
 * @retval -1 on failure.
 */
non_null()
int pack_ip_port(const Logger *logger, uint8_t *data, uint16_t length, const IP_Port *ip_port);

/** @brief Encrypt plain and write resulting DHT packet into packet with max size length.
 *
 * @return size of packet on success.
 * @retval -1 on failure.
 */
non_null()
int dht_create_packet(const Random *rng,
                      const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                      const uint8_t *shared_key, const uint8_t type,
                      const uint8_t *plain, size_t plain_length,
                      uint8_t *packet, size_t length);

/** @brief Unpack IP_Port structure from data of max size length into ip_port.
 *
 * len_processed is the offset of data currently unpacked.
 *
 * @return size of unpacked ip_port on success.
 * @retval -1 on failure.
 */
non_null()
int unpack_ip_port(IP_Port *ip_port, const uint8_t *data, uint16_t length, bool tcp_enabled);

/** @brief Pack number of nodes into data of maxlength length.
 *
 * @return length of packed nodes on success.
 * @retval -1 on failure.
 */
non_null()
int pack_nodes(const Logger *logger, uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number);

/** @brief Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * @return number of unpacked nodes on success.
 * @retval -1 on failure.
 */
non_null(1, 4) nullable(3)
int unpack_nodes(Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
                 uint16_t length, bool tcp_enabled);


/*----------------------------------------------------------------------------------*/
/* struct to store some shared keys so we don't have to regenerate them for each request. */
#define MAX_KEYS_PER_SLOT 4
#define KEYS_TIMEOUT 600

typedef struct Shared_Key {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    uint32_t times_requested;
    bool stored;
    uint64_t time_last_requested;
} Shared_Key;

typedef struct Shared_Keys {
    Shared_Key keys[256 * MAX_KEYS_PER_SLOT];
} Shared_Keys;

/*----------------------------------------------------------------------------------*/

typedef int cryptopacket_handler_cb(void *object, const IP_Port *ip_port, const uint8_t *source_pubkey,
                                    const uint8_t *data, uint16_t len, void *userdata);

typedef struct DHT DHT;

non_null() const uint8_t *dht_get_self_public_key(const DHT *dht);
non_null() const uint8_t *dht_get_self_secret_key(const DHT *dht);
non_null() void dht_set_self_public_key(DHT *dht, const uint8_t *key);
non_null() void dht_set_self_secret_key(DHT *dht, const uint8_t *key);

non_null() Networking_Core *dht_get_net(const DHT *dht);
non_null() struct Ping *dht_get_ping(const DHT *dht);
non_null() const Client_data *dht_get_close_clientlist(const DHT *dht);
non_null() const Client_data *dht_get_close_client(const DHT *dht, uint32_t client_num);
non_null() uint16_t dht_get_num_friends(const DHT *dht);

non_null() DHT_Friend *dht_get_friend(DHT *dht, uint32_t friend_num);
non_null() const uint8_t *dht_get_friend_public_key(const DHT *dht, uint32_t friend_num);

/*----------------------------------------------------------------------------------*/

/**
 * Shared key generations are costly, it is therefore smart to store commonly used
 * ones so that they can be re-used later without being computed again.
 *
 * If a shared key is already in shared_keys, copy it to shared_key.
 * Otherwise generate it into shared_key and copy it to shared_keys
 */
non_null()
void get_shared_key(
    const Mono_Time *mono_time, Shared_Keys *shared_keys, uint8_t *shared_key,
    const uint8_t *secret_key, const uint8_t *public_key);

/**
 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we receive.
 */
non_null()
void dht_get_shared_key_recv(DHT *dht, uint8_t *shared_key, const uint8_t *public_key);

/**
 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we send.
 */
non_null()
void dht_get_shared_key_sent(DHT *dht, uint8_t *shared_key, const uint8_t *public_key);

/**
 * Sends a getnodes request to `ip_port` with the public key `public_key` for nodes
 * that are close to `client_id`.
 *
 * @retval true on success.
 */
non_null()
bool dht_getnodes(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key, const uint8_t *client_id);

typedef void dht_ip_cb(void *object, int32_t number, const IP_Port *ip_port);

typedef void dht_get_nodes_response_cb(const DHT *dht, const Node_format *node, void *user_data);

/** Sets the callback to be triggered on a getnodes response. */
non_null(1) nullable(2)
void dht_callback_get_nodes_response(DHT *dht, dht_get_nodes_response_cb *function);

/** @brief Add a new friend to the friends list.
 * public_key must be CRYPTO_PUBLIC_KEY_SIZE bytes long.
 *
 * ip_callback is the callback of a function that will be called when the ip address
 * is found along with arguments data and number.
 *
 * lock_count will be set to a non zero number that must be passed to `dht_delfriend()`
 * to properly remove the callback.
 *
 * @retval 0 if success.
 * @retval -1 if failure (friends list is full).
 */
non_null(1, 2) nullable(3, 4, 6)
int dht_addfriend(DHT *dht, const uint8_t *public_key, dht_ip_cb *ip_callback,
                  void *data, int32_t number, uint16_t *lock_count);

/** @brief Delete a friend from the friends list.
 * public_key must be CRYPTO_PUBLIC_KEY_SIZE bytes long.
 *
 * @retval 0 if success.
 * @retval -1 if failure (public_key not in friends list).
 */
non_null()
int dht_delfriend(DHT *dht, const uint8_t *public_key, uint16_t lock_count);

/** @brief Get ip of friend.
 *
 * @param public_key must be CRYPTO_PUBLIC_KEY_SIZE bytes long.
 *
 * @retval -1 if public_key does NOT refer to a friend
 * @retval  0 if public_key refers to a friend and we failed to find the friend (yet)
 * @retval  1 if public_key refers to a friend and we found him
 */
non_null()
int dht_getfriendip(const DHT *dht, const uint8_t *public_key, IP_Port *ip_port);

/** @brief Compares pk1 and pk2 with pk.
 *
 * @retval 0 if both are same distance.
 * @retval 1 if pk1 is closer.
 * @retval 2 if pk2 is closer.
 */
non_null()
int id_closest(const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2);

/** Return index of first unequal bit number between public keys pk1 and pk2. */
non_null()
unsigned int bit_by_bit_cmp(const uint8_t *pk1, const uint8_t *pk2);

/**
 * Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 *
 * @return true iff the node was added to the list.
 */
non_null()
bool add_to_list(
    Node_format *nodes_list, uint32_t length, const uint8_t *pk, const IP_Port *ip_port, const uint8_t *cmp_pk);

/** Return 1 if node can be added to close list, 0 if it can't. */
non_null()
bool node_addable_to_close_list(DHT *dht, const uint8_t *public_key, const IP_Port *ip_port);

#ifdef CHECK_ANNOUNCE_NODE
/** Set node as announce node. */
non_null()
void set_announce_node(DHT *dht, const uint8_t *public_key);
#endif

/**
 * Get the (maximum MAX_SENT_NODES) closest nodes to public_key we know
 * and put them in nodes_list (must be MAX_SENT_NODES big).
 *
 * sa_family = family (IPv4 or IPv6) (0 if we don't care)?
 * is_LAN = return some LAN ips (true or false)
 * want_announce: return only nodes which implement the dht announcements protocol.
 *
 * @return the number of nodes returned.
 */
non_null()
int get_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list, Family sa_family,
                    bool is_LAN, bool want_announce);


/** @brief Put up to max_num nodes in nodes from the random friends.
 *
 * Important: this function relies on the first two DHT friends *not* being real
 * friends to avoid leaking information about real friends into the onion paths.
 *
 * @return the number of nodes.
 */
non_null()
uint16_t randfriends_nodes(const DHT *dht, Node_format *nodes, uint16_t max_num);

/** @brief Put up to max_num nodes in nodes from the closelist.
 *
 * @return the number of nodes.
 */
non_null()
uint16_t closelist_nodes(const DHT *dht, Node_format *nodes, uint16_t max_num);

/** Run this function at least a couple times per second (It's the main loop). */
non_null()
void do_dht(DHT *dht);

/*
 *  Use these two functions to bootstrap the client.
 */
/**
 * @brief Sends a "get nodes" request to the given node with ip, port and public_key
 *   to setup connections
 */
non_null()
bool dht_bootstrap(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key);

/** @brief Resolves address into an IP address.
 *
 * If successful, sends a "get nodes" request to the given node with ip, port
 * and public_key to setup connections
 *
 * @param address can be a hostname or an IP address (IPv4 or IPv6).
 * @param ipv6enabled if false, the resolving sticks STRICTLY to IPv4 addresses.
 *   Otherwise, the resolving looks for IPv6 addresses first, then IPv4 addresses.
 *
 * @retval 1 if the address could be converted into an IP address
 * @retval 0 otherwise
 */
non_null()
int dht_bootstrap_from_address(DHT *dht, const char *address, bool ipv6enabled,
                               uint16_t port, const uint8_t *public_key);

/** @brief Start sending packets after DHT loaded_friends_list and loaded_clients_list are set.
 *
 * @retval 0 if successful
 * @retval -1 otherwise
 */
non_null()
int dht_connect_after_load(DHT *dht);

/* ROUTING FUNCTIONS */

/** @brief Send the given packet to node with public_key.
 *
 * @return number of bytes sent.
 * @retval -1 if failure.
 */
non_null()
int route_packet(const DHT *dht, const uint8_t *public_key, const uint8_t *packet, uint16_t length);

/**
 * Send the following packet to everyone who tells us they are connected to friend_id.
 *
 * @return ip for friend.
 * @return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 4).
 */
non_null()
uint32_t route_to_friend(const DHT *dht, const uint8_t *friend_id, const Packet *packet);

/** Function to handle crypto packets. */
non_null(1) nullable(3, 4)
void cryptopacket_registerhandler(DHT *dht, uint8_t byte, cryptopacket_handler_cb *cb, void *object);

/* SAVE/LOAD functions */

/** Get the size of the DHT (for saving). */
non_null()
uint32_t dht_size(const DHT *dht);

/** Save the DHT in data where data is an array of size `dht_size()`. */
non_null()
void dht_save(const DHT *dht, uint8_t *data);

/** @brief Load the DHT from data of size size.
 *
 * @retval -1 if failure.
 * @retval 0 if success.
 */
non_null()
int dht_load(DHT *dht, const uint8_t *data, uint32_t length);

/** Initialize DHT. */
non_null()
DHT *new_dht(const Logger *log, const Random *rng, const Network *ns, Mono_Time *mono_time, Networking_Core *net,
             bool hole_punching_enabled, bool lan_discovery_enabled);

nullable(1)
void kill_dht(DHT *dht);

/**
 * @retval false if we are not connected to the DHT.
 * @retval true if we are.
 */
non_null()
bool dht_isconnected(const DHT *dht);

/**
 * @retval false if we are not connected or only connected to lan peers with the DHT.
 * @retval true if we are.
 */
non_null()
bool dht_non_lan_connected(const DHT *dht);

/** @brief Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.
 *
 * @return 1+ if the item is used in any list, 0 else
 */
non_null()
uint32_t addto_lists(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key);

/** @brief Copies our own ip_port structure to `dest`.
 *
 * WAN addresses take priority over LAN addresses.
 *
 * This function will zero the `dest` buffer before use.
 *
 * @retval 0 if our ip port can't be found (this usually means we're not connected to the DHT).
 * @retval 1 if IP is a WAN address.
 * @retval 2 if IP is a LAN address.
 */
non_null()
unsigned int ipport_self_copy(const DHT *dht, IP_Port *dest);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
