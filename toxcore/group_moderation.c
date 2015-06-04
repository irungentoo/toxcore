/* group_moderation.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "util.h"
#include "network.h"
#include "group_chats.h"
#include "group_connection.h"
#include "group_moderation.h"

/* Unpacks data into the moderator list.
 * data should contain num_mods entries of size GC_MOD_LIST_ENTRY_SIZE.
 *
 * Returns length of unpacked data on success.
 * Returns -1 on failure.
 */
int mod_list_unpack(GC_Chat *chat, const uint8_t *data, uint32_t length, uint16_t num_mods)
{
    if (length != num_mods * GC_MOD_LIST_ENTRY_SIZE)
        return -1;

    mod_list_cleanup(chat);

    if (num_mods == 0)
        return 0;

    uint8_t **tmp_list = malloc(sizeof(uint8_t *) * num_mods);

    if (tmp_list == NULL)
        return -1;

    uint32_t unpacked_len = 0;
    uint16_t i;

    for (i = 0; i < num_mods; ++i) {
        tmp_list[i] = malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

        if (tmp_list[i] == NULL)
            return -1;

        memcpy(tmp_list[i], &data[i * GC_MOD_LIST_ENTRY_SIZE], GC_MOD_LIST_ENTRY_SIZE);
        unpacked_len += GC_MOD_LIST_ENTRY_SIZE;
    }

    chat->moderation.mod_list = tmp_list;
    chat->moderation.num_mods = num_mods;

    return unpacked_len;
}

/* Packs moderator list into data.
 * data must have room for num_mods * SIG_PUBLIC_KEY bytes..
 */
void mod_list_pack(const GC_Chat *chat, uint8_t *data)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods && i < MAX_GC_MODERATORS; ++i)
        memcpy(&data[i * GC_MOD_LIST_ENTRY_SIZE], chat->moderation.mod_list[i], GC_MOD_LIST_ENTRY_SIZE);
}

/* Creates a new moderator list hash and puts it in hash.
 * hash must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 */
void mod_list_make_hash(GC_Chat *chat, uint8_t *hash)
{
    if (chat->moderation.num_mods == 0) {
        memset(hash, 0, GC_MOD_LIST_HASH_SIZE);
        return;
    }

    uint8_t data[chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE];
    mod_list_pack(chat, data);
    crypto_hash_sha256(hash, data, sizeof(data));
}

/* Returns moderator list index for peernumber.
 * Returns -1 if peernumber is not in the list.
 */
int mod_list_index_of_peernum(const GC_Chat *chat, uint32_t peernumber)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (memcmp(chat->moderation.mod_list[i], SIG_PK(chat->gcc[peernumber].addr.public_key), SIG_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

/* Returns true if the public signature key belongs to a moderator or the founder */
static bool mod_list_verify_sig_pk(const GC_Chat *chat, const uint8_t *sig_pk)
{
    if (memcmp(SIG_PK(chat->shared_state.founder_public_key), sig_pk, SIG_PUBLIC_KEY) == 0)
        return true;

    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (memcmp(chat->moderation.mod_list[i], sig_pk, SIG_PUBLIC_KEY) == 0)
            return true;
    }

    return false;
}

/* Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(GC_Chat *chat, size_t index)
{
    if (index >= chat->moderation.num_mods)
        return -1;

    if (chat->moderation.num_mods - 1 == 0) {
        mod_list_cleanup(chat);
        return 0;
    }

    --chat->moderation.num_mods;

    if (index != chat->moderation.num_mods)
        memcpy(chat->moderation.mod_list[index], chat->moderation.mod_list[chat->moderation.num_mods], GC_MOD_LIST_ENTRY_SIZE);

    free(chat->moderation.mod_list[chat->moderation.num_mods]);
    chat->moderation.mod_list[chat->moderation.num_mods] = NULL;

    uint8_t **tmp_list = realloc(chat->moderation.mod_list, sizeof(uint8_t *) * chat->moderation.num_mods);

    if (tmp_list == NULL)
        return -1;

    chat->moderation.mod_list = tmp_list;

    return 0;
}

/* Removes peernumber from the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_peer(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->moderation.num_mods == 0)
        return -1;

    int idx = mod_list_index_of_peernum(chat, peernumber);

    if (idx == -1)
        return -1;

    return mod_list_remove_index(chat, idx);
}

/* Adds peernumber to the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_add_peer(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->moderation.num_mods >= MAX_GC_MODERATORS)
        return -1;

    uint8_t **tmp_list = realloc(chat->moderation.mod_list, sizeof(uint8_t *) * (chat->moderation.num_mods + 1));

    if (tmp_list == NULL) {
        chat->moderation.num_mods = 0;
        return -1;
    }

    tmp_list[chat->moderation.num_mods] = malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

    if (tmp_list[chat->moderation.num_mods] == NULL)
        return -1;

    memcpy(tmp_list[chat->moderation.num_mods], SIG_PK(chat->gcc[peernumber].addr.public_key), GC_MOD_LIST_ENTRY_SIZE);
    chat->moderation.mod_list = tmp_list;
    ++chat->moderation.num_mods;

    return 0;
}

/* Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(GC_Chat *chat)
{
    free_uint8_t_pointer_array(chat->moderation.mod_list, chat->moderation.num_mods);
    chat->moderation.num_mods = 0;
    chat->moderation.mod_list = NULL;
}

/* Packs num_sanctions sanctions into data of maxlength length.
 *
 * Returns length of packed data on success.
 * Returns -1 on failure.
 */
int sanctions_list_pack(uint8_t *data, uint16_t length, struct GC_Sanction *sanctions, uint16_t num_sanctions)
{
    uint16_t i, packed_len = 0;

    for (i = 0; i < num_sanctions && i < MAX_GC_SANCTIONS; ++i) {
        if (packed_len + sizeof(uint8_t) + SIG_PUBLIC_KEY + TIME_STAMP_SIZE > length)
            return -1;

        memcpy(data + packed_len, &sanctions[i].type, sizeof(uint8_t));
        packed_len += sizeof(uint8_t);
        memcpy(data + packed_len, sanctions[i].public_sig_key, SIG_PUBLIC_KEY);
        packed_len += SIG_PUBLIC_KEY;
        U64_to_bytes(data + packed_len, sanctions[i].time_set);
        packed_len += TIME_STAMP_SIZE;

        if (sanctions[i].type == SA_BAN) {
            int ipp_size = pack_ip_port(data, length, packed_len, &sanctions[i].ban_info.ip_port);

            if (ipp_size == -1 || ipp_size + sizeof(uint16_t) + sizeof(uint32_t) + MAX_GC_NICK_SIZE > length)
                return -1;

            packed_len += ipp_size;
            memcpy(data + packed_len, sanctions[i].ban_info.nick, MAX_GC_NICK_SIZE);
            packed_len += MAX_GC_NICK_SIZE;
            U16_to_bytes(data + packed_len, sanctions[i].ban_info.nick_len);
            packed_len += sizeof(uint16_t);
            U32_to_bytes(data + packed_len, sanctions[i].ban_info.id);
            packed_len += sizeof(uint32_t);
        } else if (sanctions[i].type == SA_OBSERVER) {
            if (packed_len + ENC_PUBLIC_KEY > length)
                return -1;

            memcpy(data + packed_len, sanctions[i].target_pk, ENC_PUBLIC_KEY);
            packed_len += ENC_PUBLIC_KEY;
        } else {
            return -1;
        }

        if (packed_len + SIGNATURE_SIZE > length)
            return -1;

        /* Signature must be packed last */
        memcpy(data + packed_len, sanctions[i].signature, SIGNATURE_SIZE);
        packed_len += SIGNATURE_SIZE;
    }

    return packed_len;
}

/* Unpack data of length into sanctions of size max_sanctions.
 * Put the length of the data processed in processed_data_len/
 *
 * Returns number of unpacked entries on success.
 * Returns -1 on failure.
 */
int sanctions_list_unpack(struct GC_Sanction *sanctions, uint16_t max_sanctions, const uint8_t *data,
                          uint16_t length, uint16_t *processed_data_len)
{
    uint16_t num = 0, len_processed = 0;

    while (num < max_sanctions && num < MAX_GC_SANCTIONS && len_processed < length) {
        if (len_processed + sizeof(uint8_t) + SIG_PUBLIC_KEY + TIME_STAMP_SIZE > length)
            return -1;

        memcpy(&sanctions[num].type, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(sanctions[num].public_sig_key, data + len_processed, SIG_PUBLIC_KEY);
        len_processed += SIG_PUBLIC_KEY;
        bytes_to_U64(&sanctions[num].time_set, data + len_processed);
        len_processed += TIME_STAMP_SIZE;

        if (sanctions[num].type == SA_BAN) {
            int ipp_size = unpack_ip_port(&sanctions[num].ban_info.ip_port, len_processed, data, length, 1);

            if (ipp_size == -1 || ipp_size + sizeof(uint16_t) + sizeof(uint32_t) + MAX_GC_NICK_SIZE > length)
                return -1;

            len_processed += ipp_size;
            memcpy(sanctions[num].ban_info.nick, data + len_processed, MAX_GC_NICK_SIZE);
            len_processed += MAX_GC_NICK_SIZE;
            bytes_to_U16(&sanctions[num].ban_info.nick_len, data + len_processed);
            len_processed += sizeof(uint16_t);
            bytes_to_U32(&sanctions[num].ban_info.id, data + len_processed);
            len_processed += sizeof(uint32_t);
        } else if (sanctions[num].type == SA_OBSERVER) {
            if (len_processed + ENC_PUBLIC_KEY > length)
                return -1;

            memcpy(sanctions[num].target_pk, data + len_processed, ENC_PUBLIC_KEY);
            len_processed += ENC_PUBLIC_KEY;
        } else {
            return -1;
        }

        if (len_processed + SIGNATURE_SIZE > length)
            return -1;

        memcpy(sanctions[num].signature, data + len_processed, SIGNATURE_SIZE);
        len_processed += SIGNATURE_SIZE;

        ++num;
    }

    if (processed_data_len)
        *processed_data_len = len_processed;

    return num;
}

/* Removes index-th sanctions list entry.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_remove_index(GC_Chat *chat, size_t index)
{
    if (index >= chat->moderation.num_sanctions)
        return -1;

    --chat->moderation.num_sanctions;

    if (chat->moderation.num_sanctions == 0) {
        sanctions_list_cleanup(chat);
        return 0;
    }

    if (index != chat->moderation.num_sanctions)
        memcpy(&chat->moderation.sanctions[index], &chat->moderation.sanctions[chat->moderation.num_sanctions],
               sizeof(struct GC_Sanction));

    memset(&chat->moderation.sanctions[chat->moderation.num_sanctions], 0, sizeof(struct GC_Sanction));

    struct GC_Sanction *tmp_list = realloc(chat->moderation.sanctions,
                                            sizeof(struct GC_Sanction) * chat->moderation.num_sanctions);
    if (tmp_list == NULL)
        return -1;

    chat->moderation.sanctions = tmp_list;

    return 0;
}

/* Removes ban entry with ban_id from sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found
 */
int sanctions_list_remove_ban(GC_Chat *chat, uint32_t ban_id)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (chat->moderation.sanctions[i].ban_info.id == ban_id)
            return sanctions_list_remove_index(chat, i);
    }

    return -1;
}

/* Removes observer entry for public key from sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found.
 */
int sanctions_list_remove_observer(GC_Chat *chat, const uint8_t *public_key)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_OBSERVER)
            continue;

        if (memcmp(public_key, chat->moderation.sanctions[i].target_pk, ENC_PUBLIC_KEY) == 0)
            return sanctions_list_remove_index(chat, i);
    }

    return -1;
}

/* Returns true if the IP address is in the ban list.
 * All sanctions list entries are assumed to be verified
 */
bool sanctions_list_ip_banned(const GC_Chat *chat, IP_Port *ip_port)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (ip_equal(&chat->moderation.sanctions[i].ban_info.ip_port.ip, &ip_port->ip))
            return true;
    }

    return false;
}

/* Returns true if peernumber is in the observer list.
 * All sanction list entries are assumed to be verified.
 */
bool sanctions_list_is_observer(const GC_Chat *chat, uint32_t peernumber)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_OBSERVER)
            continue;

        if (memcmp(chat->moderation.sanctions[i].target_pk,
                   chat->gcc[peernumber].addr.public_key, ENC_PUBLIC_KEY) == 0)
            return true;
    }

    return false;
}

/* Verifies that sanction was assigned by a current mod or group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_validate_entry(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    if (!mod_list_verify_sig_pk(chat, sanction->public_sig_key)) {
        fprintf(stderr, "mod_list_verify_sig_pk failed\n");
        return -1;
    }

    if (sanction->type >= SA_INVALID)
        return -1;

    uint8_t packed_data[sizeof(struct GC_Sanction)];
    int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, 1);

    if (packed_len <= SIGNATURE_SIZE)
        return -1;

    return crypto_sign_verify_detached(sanction->signature, packed_data, packed_len - SIGNATURE_SIZE,
                                       sanction->public_sig_key);
}

/* Validates all sanctions list entries.
 *
 * Returns 0 if all entries are valid.
 * Returns -1 if one or more entries are invalid.
 */
int sanctions_list_check_integrity(const GC_Chat *chat, struct GC_Sanction *sanctions, uint16_t num_sanctions)
{
    uint16_t i;

    for (i = 0; i < num_sanctions; ++i) {
        if (sanctions_list_validate_entry(chat, &sanctions[i]) == -1)
            return -1;
    }

    return 0;
}

/* Validates entry and adds it to the sanctions list.
 * Entries must be unique.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_add_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction)
{
    if (chat->moderation.num_sanctions >= MAX_GC_SANCTIONS)
        return -1;   // TODO: remove oldest entry and continue

    if (sanctions_list_validate_entry(chat, sanction) == -1)
        return -1;

    if (sanction->type == SA_BAN) {
        if (sanctions_list_ip_banned(chat, &chat->gcc[peernumber].addr.ip_port))
            return -1;
    } else if (sanction->type == SA_OBSERVER) {
        if (sanctions_list_is_observer(chat, peernumber))
            return -1;
    }

    size_t index = chat->moderation.num_sanctions;
    struct GC_Sanction *tmp_list = realloc(chat->moderation.sanctions, sizeof(struct GC_Sanction) * (index + 1));

    if (tmp_list == NULL)
        return -1;

    memcpy(&tmp_list[index], sanction, sizeof(struct GC_Sanction));
    chat->moderation.sanctions = tmp_list;
    ++chat->moderation.num_sanctions;

    return 0;
}

/* Signs packed sanction data.
 * This function must be called by the owner of the entry's public_sig_key.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_sign_entry(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    uint8_t packed_data[sizeof(struct GC_Sanction)];
    int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, 1);

    if (packed_len <= SIGNATURE_SIZE)
        return -1;

    return crypto_sign_detached(sanction->signature, NULL, packed_data, packed_len - SIGNATURE_SIZE,
                                SIG_SK(chat->self_secret_key));
}

/* Gets a unique ID for each new ban. */
static uint32_t get_new_ban_id(const GC_Chat *chat)
{
    uint16_t i, new_id = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (chat->moderation.sanctions[i].ban_info.id >= new_id)
            new_id = chat->moderation.sanctions[i].ban_info.id + 1;
    }

    return new_id;
}

/* Creates a new sanction entry for peernumber where type is one GROUP_SANCTION_TYPE.
 * New entry is signed and placed in the sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction, uint8_t type)
{
    memset(sanction, 0, sizeof(struct GC_Sanction));

    if (type == SA_BAN) {
        ipport_copy(&sanction->ban_info.ip_port, &chat->gcc[peernumber].addr.ip_port);
        memcpy(sanction->ban_info.nick, chat->group[peernumber].nick, MAX_GC_NICK_SIZE);
        sanction->ban_info.nick_len = chat->group[peernumber].nick_len;
        sanction->ban_info.id = get_new_ban_id(chat);
    } else if (type == SA_OBSERVER) {
        memcpy(sanction->target_pk, chat->gcc[peernumber].addr.public_key, ENC_PUBLIC_KEY);
    } else {
        return -1;
    }

    memcpy(sanction->public_sig_key, SIG_PK(chat->self_public_key), SIG_PUBLIC_KEY);
    sanction->time_set = unix_time();
    sanction->type = type;

    if (sanctions_list_sign_entry(chat, sanction) == -1)
        return -1;

    if (sanctions_list_add_entry(chat, peernumber, sanction) == -1) {
        fprintf(stderr, "sanctions_list_add_entry failed in sanctions_list_make_entry\n");
        return -1;
    }

    return 0;
}

/* Returns the number of sanctions list entries that are of type SA_BAN */
uint16_t sanctions_list_num_banned(const GC_Chat *chat)
{
    uint16_t i, count = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN)
            ++count;
    }

    return count;
}

/* Replaces all sanctions list signatures made by public_sig_key with the caller's.
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
uint16_t sanctions_list_replace_sig(GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint16_t i, count = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (memcmp(chat->moderation.sanctions[i].public_sig_key, public_sig_key, SIG_PUBLIC_KEY) != 0)
            continue;

        memcpy(chat->moderation.sanctions[i].public_sig_key, SIG_PK(chat->self_public_key), SIG_PUBLIC_KEY);

        if (sanctions_list_sign_entry(chat, &chat->moderation.sanctions[i]) != -1)
            ++count;
    }

    return count;
}

void sanctions_list_cleanup(GC_Chat *chat)
{
    if (chat->moderation.sanctions)
        free(chat->moderation.sanctions);

    chat->moderation.sanctions = NULL;
    chat->moderation.num_sanctions = 0;
}
