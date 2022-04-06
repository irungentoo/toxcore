/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Similar to ping.h, but designed for group chat purposes
 */
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include <stdbool.h>

#include "DHT.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The maximum number of announces to save for a particular group chat. */
#define GCA_MAX_SAVED_ANNOUNCES_PER_GC 16

/* Maximum number of TCP relays that can be in an annoucne. */
#define GCA_MAX_ANNOUNCED_TCP_RELAYS 1

/* Maximum number of announces we can send in an announce response. */
#define GCA_MAX_SENT_ANNOUNCES 4

/* Maximum size of an announce. */
#define GCA_ANNOUNCE_MAX_SIZE (ENC_PUBLIC_KEY_SIZE + 1 + 1 + (PACKED_NODE_SIZE_IP6 * 2))

/* Maximum size of a public announce. */
#define GCA_PUBLIC_ANNOUNCE_MAX_SIZE (ENC_PUBLIC_KEY_SIZE + GCA_ANNOUNCE_MAX_SIZE)

typedef struct GC_Announce GC_Announce;
typedef struct GC_Peer_Announce GC_Peer_Announce;
typedef struct GC_Announces GC_Announces;
typedef struct GC_Announces_List GC_Announces_List;
typedef struct GC_Public_Announce GC_Public_Announce;

/* Base announce. */
struct GC_Announce {
    Node_format tcp_relays[GCA_MAX_ANNOUNCED_TCP_RELAYS];
    uint8_t tcp_relays_count;
    bool ip_port_is_set;
    IP_Port ip_port;
    uint8_t peer_public_key[ENC_PUBLIC_KEY_SIZE];
};

/* Peer announce for specific group. */
struct GC_Peer_Announce {
    GC_Announce base_announce;
    uint64_t timestamp;
};

/* Used for announces in public groups. */
struct GC_Public_Announce {
    GC_Announce base_announce;
    uint8_t chat_public_key[ENC_PUBLIC_KEY_SIZE];
};

/* A linked list that holds all announces for a particular group. */
struct GC_Announces {
    uint8_t chat_id[CHAT_ID_SIZE];
    uint64_t index;
    uint64_t last_announce_received_timestamp;

    GC_Peer_Announce peer_announces[GCA_MAX_SAVED_ANNOUNCES_PER_GC];

    GC_Announces *next_announce;
    GC_Announces *prev_announce;
};

/* A list of all announces. */
struct GC_Announces_List {
    GC_Announces *root_announces;
    uint64_t last_timeout_check;
};


/** @brief Returns a new group announces list.
 *
 * The caller is responsible for freeing the memory with `kill_gca`.
 */
GC_Announces_List *new_gca_list(void);

/** @brief Frees all dynamically allocated memory associated with `announces_list`. */
nullable(1)
void kill_gca(GC_Announces_List *announces_list);

/** @brief Iterates through the announces list and removes announces that are considered stale.
 *
 * @param gc_announces_list The list of announces to iterate.
 *
 * This function should be called from the main loop, and will iterate the list a
 * maxmimum of once per second.
 */
non_null()
void do_gca(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list);

/** @brief Frees all dynamically allocated memory associated with an announces list entry.
 *
 * @param gc_announces_list The announces list we want to search through.
 * @param chat_id The chat ID that designates the entry we want to remove.
 */
non_null()
void cleanup_gca(GC_Announces_List *gc_announces_list, const uint8_t *chat_id);

/** @brief Puts a set of announces from the announces list in supplied list.
 *
 * @param gc_announces_list The announces list we want to search for entries in.
 * @param gc_announces An empty announces list that will be filled with matches.
 * @param max_nodes The maximum number of matches that we want to add to the list.
 * @param chat_id The chat ID associated with the announces that we want to add.
 * @param except_public_key The public key associated with announces that we want to ignore.
 *
 * @return the number of added nodes on success.
 * @retval -1 on failure.
 */
non_null()
int gca_get_announces(const GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                      const uint8_t *chat_id, const uint8_t *except_public_key);

/** @brief Adds a public_announce to list of announces.
 *
 * @param gc_announces_list The announces list that we want to add an entry to.
 * @param public_announce The public announce that we want to add.
 *
 * @return the peer announce on success.
 * @retval null on failure.
 */
non_null()
GC_Peer_Announce *gca_add_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list,
                                   const GC_Public_Announce *public_announce);

/** @brief Packs an announce into a data buffer.
 *
 * @param data The data buffer being packed.
 * @param length The size in bytes of the data buffer. Must be at least GCA_ANNOUNCE_MAX_SIZE.
 * @param announce The announce being packed into the data buffer.
 *
 * @return the size of the packed data on success.
 * @retval -1 on failure.
 */
non_null()
int gca_pack_announce(const Logger *log, uint8_t *data, uint16_t length, const GC_Announce *announce);

/** @brief Returns the number of bytes needed for a buff in which to pack `count` announces. */
uint16_t gca_pack_announces_list_size(uint16_t count);

/** @brief Packs a list of announces into a data buffer.
 *
 * @param data The data buffer being packed.
 * @param length The size in bytes of the data buffer. Use gca_pack_announces_list_size to get the
 *   required length.
 * @param announces The announces to be packed into the data buffer.
 * @param announces_count The number of announces in the announces list.
 * @param processed If non-null, will contain the number of bytes packed (only on success).
 *
 * @return the number of packed announces on success.
 * @retval -1 on failure.
 */
non_null(1, 2, 4) nullable(6)
int gca_pack_announces_list(const Logger *log, uint8_t *data, uint16_t length, const GC_Announce *announces,
                            uint8_t announces_count, size_t *processed);

/** @brief Unpacks packed announces from a data buffer into a supplied list.
 *
 * @param data The data buffer to unpack from.
 * @param length The size of the data buffer.
 * @param announces The announces list that the data buffer will be unpacked to.
 * @param max_count The maximum number of announces to unpack.
 *
 * @return the number of unpacked announces on success.
 * @retval -1 on failure.
 */
non_null()
int gca_unpack_announces_list(const Logger *log, const uint8_t *data, uint16_t length, GC_Announce *announces,
                              uint8_t max_count);

/** @brief Packs a public announce into a data buffer.
 *
 * @param data The data buffer being packed.
 * @param length The size in bytes of the data buffer. Must be at least GCA_PUBLIC_ANNOUNCE_MAX_SIZE.
 * @param public_announce The public announce being packed into the data buffer.
 *
 * @return the size of the packed data on success.
 * @retval -1 on failure.
 */
non_null()
int gca_pack_public_announce(const Logger *log, uint8_t *data, uint16_t length,
                             const GC_Public_Announce *public_announce);

/** @brief Unpacks a public announce from a data buffer into a supplied public announce.
 *
 * @param data The data buffer to unpack from.
 * @param length The size of the data buffer.
 * @param public_announce The public announce to unpack the data buffer into.
 *
 * @return the size of the unpacked data on success.
 * @retval -1 on failure.
 */
non_null()
int gca_unpack_public_announce(const Logger *log, const uint8_t *data, uint16_t length,
                               GC_Public_Announce *public_announce);

/** @brief Returns true if the announce is valid.
 *
 * An announce is considered valid if there is at least one TCP relay, or the ip_port is set.
 */
non_null()
bool gca_is_valid_announce(const GC_Announce *announce);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // GROUP_ANNOUNCE_H
