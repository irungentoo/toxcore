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
int mod_list_unpack(GC_Chat *chat, const uint8_t *data, uint32_t length, uint32_t num_mods)
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

        if (tmp_list[i] == NULL) {
            free_uint8_t_pointer_array(tmp_list, i);
            return -1;
        }

        memcpy(tmp_list[i], &data[i * GC_MOD_LIST_ENTRY_SIZE], GC_MOD_LIST_ENTRY_SIZE);
        unpacked_len += GC_MOD_LIST_ENTRY_SIZE;
    }

    chat->moderation.mod_list = tmp_list;
    chat->moderation.num_mods = num_mods;

    return unpacked_len;
}

/* Packs moderator list into data.
 * data must have room for num_mods * GC_MOD_LIST_ENTRY_SIZE bytes.
 */
void mod_list_pack(const GC_Chat *chat, uint8_t *data)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods && i < MAX_GC_MODERATORS; ++i)
        memcpy(&data[i * GC_MOD_LIST_ENTRY_SIZE], chat->moderation.mod_list[i], GC_MOD_LIST_ENTRY_SIZE);
}

/* Creates a new moderator list hash and puts it in hash.
 * hash must have room for at least GC_MODERATION_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 */
void mod_list_make_hash(GC_Chat *chat, uint8_t *hash)
{
    if (chat->moderation.num_mods == 0) {
        memset(hash, 0, GC_MODERATION_HASH_SIZE);
        return;
    }

    uint8_t data[chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE];
    mod_list_pack(chat, data);
    crypto_hash_sha256(hash, data, sizeof(data));
}

/* Returns moderator list index for public_sig_key.
 * Returns -1 if key is not in the list.
 */
int mod_list_index_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (memcmp(chat->moderation.mod_list[i], public_sig_key, SIG_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

/* Returns true if the public signature key belongs to a moderator or the founder */
bool mod_list_verify_sig_pk(const GC_Chat *chat, const uint8_t *sig_pk)
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

/* Returns true if sig_pk is the designated sync moderator, which is defined as the
 * moderator (or founder) who has the closest signature public key to the Chat ID.
 */
bool mod_list_chosen_one(const GC_Chat *chat, const uint8_t *sig_pk)
{
    uint16_t i;

    for (i = 0; i < chat->moderation.num_mods; ++i) {
        if (id_closest(CHAT_ID(chat->chat_public_key), sig_pk, chat->moderation.mod_list[i]) == 2)
            return false;
    }

    if (id_closest(CHAT_ID(chat->chat_public_key), sig_pk,
                   SIG_PK(chat->shared_state.founder_public_key)) == 2)
        return false;

    return true;
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

    if (chat->moderation.num_mods == 0)
        return -1;

    if ((chat->moderation.num_mods - 1) == 0) {
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

/* Removes public_sig_key from the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_entry(GC_Chat *chat, const uint8_t *public_sig_key)
{
    if (chat->moderation.num_mods == 0)
        return -1;

    int idx = mod_list_index_of_sig_pk(chat, public_sig_key);

    if (idx == -1)
        return -1;

    if (mod_list_remove_index(chat, idx) == -1)
        return -1;

    return 0;
}

/* Adds a mod to the moderator list. mod_data must be GC_MOD_LIST_ENTRY_SIZE bytes.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_add_entry(GC_Chat *chat, const uint8_t *mod_data)
{
    if (chat->moderation.num_mods >= MAX_GC_MODERATORS)
        return -1;

    uint8_t **tmp_list = realloc(chat->moderation.mod_list, sizeof(uint8_t *) * (chat->moderation.num_mods + 1));

    if (tmp_list == NULL)
        return -1;

    tmp_list[chat->moderation.num_mods] = malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

    if (tmp_list[chat->moderation.num_mods] == NULL)
        return -1;

    memcpy(tmp_list[chat->moderation.num_mods], mod_data, GC_MOD_LIST_ENTRY_SIZE);
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

/* Packs sanction list credentials into data.
 * data must have room for GC_SANCTIONS_CREDENTIALS_SIZE bytes.
 *
 * Returns length of packed data.
 */
uint16_t sanctions_creds_pack(struct GC_Sanction_Creds *creds, uint8_t *data, uint16_t length)
{
    if (GC_SANCTIONS_CREDENTIALS_SIZE > length)
        return 0;

    uint16_t packed_len = 0;

    U32_to_bytes(data + packed_len, creds->version);
    packed_len += sizeof(uint32_t);
    memcpy(data + packed_len, creds->hash, GC_MODERATION_HASH_SIZE);
    packed_len += GC_MODERATION_HASH_SIZE;
    memcpy(data + packed_len, creds->sig_pk, SIG_PUBLIC_KEY);
    packed_len += SIG_PUBLIC_KEY;
    memcpy(data + packed_len, creds->sig, SIGNATURE_SIZE);
    packed_len += SIGNATURE_SIZE;

    return packed_len;
}

/* Packs num_sanctions sanctions into data of maxlength length. Additionally packs the
 * sanction list credentials into creds if creds is non-null.
 *
 * Returns length of packed data on success.
 * Returns -1 on failure.
 */
int sanctions_list_pack(uint8_t *data, uint16_t length, struct GC_Sanction *sanctions,
                        struct GC_Sanction_Creds *creds, uint32_t num_sanctions)
{
    uint32_t i, packed_len = 0;

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

    if (creds == NULL)
        return packed_len;

    uint16_t cred_len = sanctions_creds_pack(creds, data + packed_len, length - packed_len);

    if (cred_len != GC_SANCTIONS_CREDENTIALS_SIZE)
        return -1;

    return packed_len + cred_len;
}

/* Unpacks sanctions credentials into creds from data.
 * data must have room for GC_SANCTIONS_CREDENTIALS_SIZE bytes.
 *
 * Returns the length of the data processed.
 */
uint16_t sanctions_creds_unpack(struct GC_Sanction_Creds *creds, const uint8_t *data, uint16_t length)
{
    if (GC_SANCTIONS_CREDENTIALS_SIZE > length)
        return 0;

    uint16_t len_processed = 0;

    bytes_to_U32(&creds->version, data + len_processed);
    len_processed += sizeof(uint32_t);
    memcpy(creds->hash, data + len_processed, GC_MODERATION_HASH_SIZE);
    len_processed += GC_MODERATION_HASH_SIZE;
    memcpy(creds->sig_pk, data + len_processed, SIG_PUBLIC_KEY);
    len_processed += SIG_PUBLIC_KEY;
    memcpy(creds->sig, data + len_processed, SIGNATURE_SIZE);
    len_processed += SIGNATURE_SIZE;

    return len_processed;
}

/* Unpack max_sanctions sanctions from data into sanctions, and unpacks credentials into creds.
 * Put the length of the data processed in processed_data_len.
 *
 * Returns number of unpacked entries on success.
 * Returns -1 on failure.
 */
int sanctions_list_unpack(struct GC_Sanction *sanctions, struct GC_Sanction_Creds *creds, uint32_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len)
{
    uint32_t num = 0;
    uint16_t len_processed = 0;

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

    uint16_t creds_len = sanctions_creds_unpack(creds, data + len_processed, length - len_processed);

    if (creds_len != GC_SANCTIONS_CREDENTIALS_SIZE)
        return -1;

    if (processed_data_len)
        *processed_data_len = len_processed + creds_len;

    return num;
}


/* Creates a new sanction list hash and puts it in hash.
 *
 * The hash is derived from the signature of all entries plus the version number.
 * hash must have room for at least GC_MODERATION_HASH_SIZE bytes.
 *
 * If num_sanctions is 0 the hash is zeroed.
 */
void sanctions_list_make_hash(struct GC_Sanction *sanctions, uint32_t new_version, uint32_t num_sanctions,
                              uint8_t *hash)
{
    if (num_sanctions == 0 || sanctions == NULL) {
        memset(hash, 0, GC_MODERATION_HASH_SIZE);
        return;
    }

    uint32_t sig_data_size = num_sanctions * SIGNATURE_SIZE;
    uint8_t data[sig_data_size + sizeof(uint32_t)];
    uint32_t i;

    for (i = 0; i < num_sanctions; ++i)
        memcpy(&data[i * SIGNATURE_SIZE], sanctions[i].signature, SIGNATURE_SIZE);

    memcpy(&data[sig_data_size], &new_version, sizeof(uint32_t));
    crypto_hash_sha256(hash, data, sizeof(data));
}

/* Verifies that sanction contains valid info and was assigned by a current mod or group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if sanction type is SA_BAN and the ban_id is a duplicate.
 */
static int sanctions_list_validate_entry(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    if (!mod_list_verify_sig_pk(chat, sanction->public_sig_key))
        return -1;

    if (sanction->type >= SA_INVALID)
        return -1;

    if (sanction->time_set == 0)
        return -1;

    if (sanction->type == SA_BAN) {
        if (sanction->ban_info.nick_len == 0 || sanction->ban_info.nick_len > MAX_GC_NICK_SIZE)
            return -1;

        if (!ipport_isset(&sanction->ban_info.ip_port))
            return -1;

        if (sanction->ban_info.ip_port.ip.family == TCP_FAMILY)
            return -1;

        if (sanctions_list_get_ban_time_set(chat, sanction->ban_info.id) != 0)
            return -2;
    }

    uint8_t packed_data[sizeof(struct GC_Sanction)];
    int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, NULL, 1);

    if (packed_len <= (int) SIGNATURE_SIZE)
        return -1;

    if (crypto_sign_verify_detached(sanction->signature, packed_data, packed_len - SIGNATURE_SIZE,
                                    sanction->public_sig_key) == -1)
        return -1;

    return 0;
}

/* Updates sanction list credentials: increment version, replace sig_pk with your own,
 * update hash to reflect new sanction list, and sign new hash signature.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_creds(GC_Chat *chat)
{
    struct GC_Sanction_Creds old_creds;
    memcpy(&old_creds, &chat->moderation.sanctions_creds, sizeof(struct GC_Sanction_Creds));

    ++chat->moderation.sanctions_creds.version;

    memcpy(chat->moderation.sanctions_creds.sig_pk, SIG_PK(chat->self_public_key), SIG_PUBLIC_KEY);
    sanctions_list_make_hash(chat->moderation.sanctions, chat->moderation.sanctions_creds.version,
                             chat->moderation.num_sanctions, chat->moderation.sanctions_creds.hash);

    if (crypto_sign_detached(chat->moderation.sanctions_creds.sig, NULL, chat->moderation.sanctions_creds.hash,
                             GC_MODERATION_HASH_SIZE, SIG_SK(chat->self_secret_key)) == -1) {
        memcpy(&chat->moderation.sanctions_creds, &old_creds, sizeof(struct GC_Sanction_Creds));
        return -1;
    }

    return 0;
}

/* Validates sanction list credentials. Verifies that:
 * - the public signature key belongs to a mod or the founder
 * - the signature for the hash was made by the owner of the public signature key.
 * - the received hash matches our own hash of the new sanctions list
 * - the new version is >= our current version
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_creds_validate(const GC_Chat *chat, struct GC_Sanction *sanctions, struct GC_Sanction_Creds *creds,
                                    uint32_t num_sanctions)
{
    if (!mod_list_verify_sig_pk(chat, creds->sig_pk))
        return -1;

    uint8_t hash[GC_MODERATION_HASH_SIZE];
    sanctions_list_make_hash(sanctions, creds->version, num_sanctions, hash);

    if (memcmp(hash, creds->hash, GC_MODERATION_HASH_SIZE) != 0)
        return -1;

    if ((creds->version < chat->moderation.sanctions_creds.version)
        && !(creds->version == 0 && chat->moderation.sanctions_creds.version == UINT32_MAX))
        return -1;

    if (crypto_sign_verify_detached(creds->sig, hash, GC_MODERATION_HASH_SIZE, creds->sig_pk) == -1)
        return -1;

    return 0;
}

/* Validates all sanction list entries as well as its credentials.
 *
 * Returns 0 if all entries are valid.
 * Returns -1 if the list contains an invalid entry or the credentials are invalid.
 */
int sanctions_list_check_integrity(const GC_Chat *chat, struct GC_Sanction_Creds *creds,
                                   struct GC_Sanction *sanctions, uint32_t num_sanctions)
{
    uint32_t i;

    for (i = 0; i < num_sanctions; ++i) {
        if (sanctions_list_validate_entry(chat, &sanctions[i]) != 0)
            return -1;
    }

    if (sanctions_creds_validate(chat, sanctions, creds, num_sanctions) == -1)
        return -1;

    return 0;
}

/* Removes index-th sanction list entry. New credentials will be validated if creds is non-null.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_remove_index(GC_Chat *chat, uint32_t index, struct GC_Sanction_Creds *creds)
{
    if (index >= chat->moderation.num_sanctions)
        return -1;

    uint32_t new_num = chat->moderation.num_sanctions - 1;

    if (new_num == 0) {
        if (creds) {
            if (sanctions_creds_validate(chat, NULL, creds, 0) == -1)
                return -1;

            memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
        }

        sanctions_list_cleanup(chat);
        return 0;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    size_t old_size = sizeof(struct GC_Sanction) * chat->moderation.num_sanctions;
    struct GC_Sanction *sanctions_copy = malloc(old_size);

    if (sanctions_copy == NULL)
        return -1;

    memcpy(sanctions_copy, chat->moderation.sanctions, old_size);

    if (index != new_num)
        memcpy(&sanctions_copy[index], &sanctions_copy[new_num], sizeof(struct GC_Sanction));

    struct GC_Sanction *new_list = realloc(sanctions_copy, sizeof(struct GC_Sanction) * new_num);

    if (new_list == NULL) {
        free(sanctions_copy);
        return -1;
    }

    if (creds) {
        if (sanctions_creds_validate(chat, new_list, creds, new_num) == -1) {
            fprintf(stderr, "sanctions_creds_validate failed in sanctions_list_remove_index\n");
            free(new_list);
            return -1;
        }

        memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
    }

    sanctions_list_cleanup(chat);
    chat->moderation.sanctions = new_list;
    chat->moderation.num_sanctions = new_num;

    return 0;
}

/* Returns a new unique ban ID. */
static uint32_t get_new_ban_id(const GC_Chat *chat)
{
    uint32_t i, new_id = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (chat->moderation.sanctions[i].ban_info.id >= new_id)
            new_id = chat->moderation.sanctions[i].ban_info.id + 1;
    }

    return new_id;
}

/* Removes ban entry with ban_id from sanction list.
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found
 */
int sanctions_list_remove_ban(GC_Chat *chat, uint32_t ban_id, struct GC_Sanction_Creds *creds)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (chat->moderation.sanctions[i].ban_info.id == ban_id) {
            if (sanctions_list_remove_index(chat, i, creds) == -1)
                return -1;

            if (creds == NULL)
                return sanctions_list_make_creds(chat);

            return 0;
        }
    }

    return -1;
}

/* Removes observer entry for public key from sanction list.
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found.
 */
int sanctions_list_remove_observer(GC_Chat *chat, const uint8_t *public_key, struct GC_Sanction_Creds *creds)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_OBSERVER)
            continue;

        if (memcmp(public_key, chat->moderation.sanctions[i].target_pk, ENC_PUBLIC_KEY) == 0) {
            if (sanctions_list_remove_index(chat, i, creds) == -1)
                return -1;

            if (creds == NULL)
                return sanctions_list_make_creds(chat);

            return 0;
        }
    }

    return -1;
}

/* Returns true if public key is in the observer list.
 * All sanction list entries are assumed to be verified.
 */
bool sanctions_list_is_observer(const GC_Chat *chat, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_OBSERVER)
            continue;

        if (memcmp(chat->moderation.sanctions[i].target_pk, public_key, ENC_PUBLIC_KEY) == 0)
            return true;
    }

    return false;
}

/* Returns true if sanction already exists in the sanctions list. */
static bool sanctions_list_entry_exists(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    if (sanction->type == SA_BAN) {
        return sanctions_list_ip_banned(chat, &sanction->ban_info.ip_port);
    } else if (sanction->type == SA_OBSERVER) {
        return sanctions_list_is_observer(chat, sanction->target_pk);
    }

    return false;
}

static int sanctions_list_sign_entry(const GC_Chat *chat, struct GC_Sanction *sanction);

/* Re-signs and re-assigns ban ID's for all sanctions entries with a ban ID equal to ban_id.
 *
 * Note: This function does not re-distribute the sanctions list to the group which
 * you will probably want to do.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_fix_ban_id(GC_Chat *chat, uint32_t ban_id)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (chat->moderation.sanctions[i].ban_info.id != ban_id)
            continue;

        struct GC_Sanction sanction;
        memcpy(&sanction, &chat->moderation.sanctions[i], sizeof(struct GC_Sanction));

        sanction.ban_info.id = get_new_ban_id(chat);

        if (sanctions_list_remove_index(chat, i, NULL) == -1)
            return -1;

        if (sanctions_list_sign_entry(chat, &sanction) == -1)
            return -1;

        if (sanctions_list_add_entry(chat, &sanction, NULL) == -1) {
            fprintf(stderr, "sanctions_list_add_entry failed in sanctions_list_fix_ban_id\n");
            return -1;
        }

        if (sanctions_list_make_creds(chat) == -1)
            return -1;

        if (i >= chat->moderation.num_sanctions)
            break;
    }

    return 0;
}

/* Adds an entry to the sanctions list. The entry is first validated and the resulting
 * new sanction list is compared against the new credentials if necessary.
 *
 * Entries must be unique.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_add_entry(GC_Chat *chat, struct GC_Sanction *sanction, struct GC_Sanction_Creds *creds)
{
    if (chat->moderation.num_sanctions >= MAX_GC_SANCTIONS)
        return -1;   // TODO: remove oldest entry and continue


    int ret = sanctions_list_validate_entry(chat, sanction);

    if (ret == -1) {
        fprintf(stderr, "sanctions_list_validate_entry failed in add entry\n");
        return -1;
    }

    /* Duplicate ban ID: If we are the designated sync mod we re-assign the ID
     * and re-distribute the fixed sanctions list. Otherwise we ignore it.
     */
    if (ret == -2) {
        if (!mod_list_verify_sig_pk(chat, SIG_PK(chat->self_public_key)))
            return -1;

        if (!mod_list_chosen_one(chat, SIG_PK(chat->self_public_key)))
            return -1;

        if (sanctions_list_fix_ban_id(chat, sanction->ban_info.id) == -1)  // indirect recursion
            return -1;
    }

    if (sanctions_list_entry_exists(chat, sanction))
        return -1;

    /* Operate on a copy of the list in case something goes wrong. */
    size_t old_size = sizeof(struct GC_Sanction) * chat->moderation.num_sanctions;
    struct GC_Sanction *sanctions_copy = malloc(old_size);

    if (sanctions_copy == NULL)
        return -1;

    memcpy(sanctions_copy, chat->moderation.sanctions, old_size);

    size_t index = chat->moderation.num_sanctions;
    struct GC_Sanction *new_list = realloc(sanctions_copy, sizeof(struct GC_Sanction) * (index + 1));

    if (new_list == NULL) {
        free(sanctions_copy);
        return -1;
    }

    memcpy(&new_list[index], sanction, sizeof(struct GC_Sanction));

    if (creds) {
        if (sanctions_creds_validate(chat, new_list, creds, index + 1) == -1) {
            fprintf(stderr, "sanctions_creds_validate failed in add entry\n");
            free(new_list);
            return -1;
        }

        memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
    }

    sanctions_list_cleanup(chat);
    chat->moderation.sanctions = new_list;
    chat->moderation.num_sanctions = index + 1;

    if (ret == -2) {
        if (broadcast_gc_sanctions_list(chat) == -1)
            return -1;
    }

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
    int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, NULL, 1);

    if (packed_len <= (int) SIGNATURE_SIZE)
        return -1;

    return crypto_sign_detached(sanction->signature, NULL, packed_data, packed_len - SIGNATURE_SIZE,
                                SIG_SK(chat->self_secret_key));
}

/* Creates a new sanction entry for peernumber where type is one GROUP_SANCTION_TYPE.
 * New entry is signed and placed in the sanction list, and the sanction list credentials
 * are updated.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction, uint8_t type)
{
    memset(sanction, 0, sizeof(struct GC_Sanction));

    if (type == SA_BAN) {
        if (chat->gcc[peernumber].addr.ip_port.ip.family == TCP_FAMILY)
            return -1;

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

    if (sanctions_list_add_entry(chat, sanction, NULL) == -1) {
        fprintf(stderr, "sanctions_list_add_entry failed in sanctions_list_make_entry\n");
        return -1;
    }

    if (sanctions_list_make_creds(chat) == -1)
        return -1;

    return 0;
}

/* Replaces all sanction list signatures made by public_sig_key with the caller's.
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
uint32_t sanctions_list_replace_sig(GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint32_t i, count = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (memcmp(chat->moderation.sanctions[i].public_sig_key, public_sig_key, SIG_PUBLIC_KEY) != 0)
            continue;

        memcpy(chat->moderation.sanctions[i].public_sig_key, SIG_PK(chat->self_public_key), SIG_PUBLIC_KEY);

        if (sanctions_list_sign_entry(chat, &chat->moderation.sanctions[i]) != -1)
            ++count;
    }

    if (count) {
        if (sanctions_list_make_creds(chat) == -1)
            return 0;
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


/********* Ban list queries *********/


/* Returns true if the IP address is in the ban list.
 * All sanction list entries are assumed to be valid.
 */
bool sanctions_list_ip_banned(const GC_Chat *chat, IP_Port *ip_port)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type != SA_BAN)
            continue;

        if (ip_equal(&chat->moderation.sanctions[i].ban_info.ip_port.ip, &ip_port->ip))
            return true;
    }

    return false;
}

/* Returns the number of sanction list entries that are of type SA_BAN */
uint32_t sanctions_list_num_banned(const GC_Chat *chat)
{
    uint32_t i, count = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN)
            ++count;
    }

    return count;
}

/* Fills list with all valid ban ID's. */
void sanctions_list_get_ban_list(const GC_Chat *chat, uint32_t *list)
{
    if (!list)
        return;

    uint32_t i, count = 0;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN)
            list[count++] = chat->moderation.sanctions[i].ban_info.id;
    }
}

/* Returns the nick length of the ban entry associted with ban_id on success.
 * Returns 0 if ban_id does not exist.
 */
uint16_t sanctions_list_get_ban_nick_length(const GC_Chat *chat, uint32_t ban_id)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN) {
            if (chat->moderation.sanctions[i].ban_info.id == ban_id)
                return chat->moderation.sanctions[i].ban_info.nick_len;
        }
    }

    return 0;
}

/* Copies the nick associated with ban_id to nick.
 *
 * Returns 0 on success.
 * Returns -1 if ban_id does not exist.
 */
int sanctions_list_get_ban_nick(const GC_Chat *chat, uint32_t ban_id, uint8_t *nick)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN) {
            if (chat->moderation.sanctions[i].ban_info.id == ban_id) {
                memcpy(nick, chat->moderation.sanctions[i].ban_info.nick, MAX_GC_NICK_SIZE);
                return 0;
            }
        }
    }

    return -1;
}

/* Returns a timestamp indicating when the ban designated by ban_id was set.
 * Returns 0 if ban_id does not exist.
 */
uint64_t sanctions_list_get_ban_time_set(const GC_Chat *chat, uint32_t ban_id)
{
    uint32_t i;

    for (i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (chat->moderation.sanctions[i].type == SA_BAN) {
            if (chat->moderation.sanctions[i].ban_info.id == ban_id)
                return chat->moderation.sanctions[i].time_set;
        }
    }

    return 0;
}
