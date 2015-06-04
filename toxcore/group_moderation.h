/* group_moderation.h
 *
 * An implementation of massive text only group chats.
 *
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef GROUP_MODERATION_H
#define GROUP_MODERATION_H

#define MAX_GC_SANCTIONS 64

enum {
    SA_BAN,
    SA_OBSERVER,
    SA_INVALID
} GROUP_SANCTION_TYPE;

struct GC_Ban {
    IP_Port     ip_port;
    uint8_t     nick[MAX_GC_NICK_SIZE];
    uint16_t    nick_len;
    uint32_t    id;
};

/* Holds data pertaining to a peer who has been banned or demoted to observer. */
struct GC_Sanction {
    uint8_t     public_sig_key[SIG_PUBLIC_KEY];
    uint64_t    time_set;

    uint8_t     type;
    union {
        struct GC_Ban ban_info;    /* Used if type is SA_BAN */
        uint8_t       target_pk[ENC_PUBLIC_KEY];    /* Used if type is SA_OBSERVER */
    };

    /* Signature of all above packed data signed by public_sig_key */
    uint8_t     signature[SIGNATURE_SIZE];
};

/* Unpacks data into the moderator list.
 * data should contain num_mods entries of size GC_MOD_LIST_ENTRY_SIZE.
 *
 * Returns length of unpacked data on success.
 * Returns -1 on failure.
 */
int mod_list_unpack(GC_Chat *chat, const uint8_t *data, uint32_t length, uint16_t num_mods);

/* Packs moderator list into data.
 * data must have room for num_mods * SIG_PUBLIC_KEY bytes.
 */
void mod_list_pack(const GC_Chat *chat, uint8_t *data);

/* Creates a new moderator list hash and puts it in hash.
 * hash must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 */
void mod_list_make_hash(GC_Chat *chat, uint8_t *hash);

/* Returns moderator list index for peernumber.
 * Returns -1 if peernumber is not in the list.
 */
int mod_list_index_of_peernum(const GC_Chat *chat, uint32_t peernumber);

/* Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(GC_Chat *chat, size_t index);

/* Removes peernumber from the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_peer(GC_Chat *chat, uint32_t peernumber);

/* Adds peernumber to the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_add_peer(GC_Chat *chat, uint32_t peernumber);

/* Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(GC_Chat *chat);

/* Packs num_sanctions sanctions into data of maxlength length.
 *
 * Returns length of packed data on success.
 * Returns -1 on failure.
 */
int sanctions_list_pack(uint8_t *data, uint16_t length, struct GC_Sanction *sanctions, uint16_t num_sanctions);

/* Unpack data of length into sanctions of size max_sanctions.
 * Put the length of the data processed in processed_data_len/
 *
 * Returns number of unpacked entries on success.
 * Returns -1 on failure.
 */
int sanctions_list_unpack(struct GC_Sanction *sanctions, uint16_t max_sanctions, const uint8_t *data,
                         uint16_t length, uint16_t *processed_data_len);

/* Validates all sanctions list entries.
 *
 * Returns 0 if all entries are valid.
 * Returns -1 if one or more entries are invalid.
 */
int sanctions_list_check_integrity(const GC_Chat *chat, struct GC_Sanction *sanctions, uint16_t num_sanctions);

/* Validates entry and adds it to the sanctions list.
 * Entries must be unique.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_add_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction);

/* Creates a new sanction entry for peernumber where type is one GROUP_SANCTION_TYPE.
 * New entry is signed and placed in the sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction, uint8_t type);

/* Returns the number of sanctions list entries that are of type SA_BAN */
uint16_t sanctions_list_num_banned(const GC_Chat *chat);

/* Returns true if the IP address is in the ban list. */
bool sanctions_list_ip_banned(const GC_Chat *chat, IP_Port *ip_port);

/* Returns true if peernumber is in the observer list. */
bool sanctions_list_is_observer(const GC_Chat *chat, uint32_t peernumber);

/* Removes observer entry for public key from sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found.
 */
int sanctions_list_remove_observer(GC_Chat *chat, const uint8_t *public_key);

/* Removes ban entry with ban_id from sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found
 */
int sanctions_list_remove_ban(GC_Chat *chat, uint32_t ban_id);

/* Replaces all sanctions list signatures made by public_sig_key with the caller's.
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
uint16_t sanctions_list_replace_sig(GC_Chat *chat, const uint8_t *public_sig_key);

void sanctions_list_cleanup(GC_Chat *chat);

#endif /* GROUP_MODERATION_H */
