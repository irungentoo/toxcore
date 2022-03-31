/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#include "group_moderation.h"

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "ccompat.h"
#include "crypto_core.h"
#include "mono_time.h"
#include "network.h"
#include "util.h"

static_assert(MOD_SANCTIONS_CREDS_SIZE <= MAX_PACKET_SIZE_NO_HEADERS,
              "MOD_SANCTIONS_CREDS_SIZE must be <= the maximum allowed payload size");
static_assert(MOD_MAX_NUM_SANCTIONS * MOD_SANCTION_PACKED_SIZE + MOD_SANCTIONS_CREDS_SIZE <= MAX_PACKET_SIZE_NO_HEADERS,
              "MOD_MAX_NUM_SANCTIONS must be able to fit inside the maximum allowed payload size");
static_assert(MOD_MAX_NUM_MODERATORS * MOD_LIST_ENTRY_SIZE <= MAX_PACKET_SIZE_NO_HEADERS,
              "MOD_MAX_NUM_MODERATORS must be able to fit insize the maximum allowed payload size");

uint16_t mod_list_packed_size(const Moderation *moderation)
{
    return moderation->num_mods * MOD_LIST_ENTRY_SIZE;
}

int mod_list_unpack(Moderation *moderation, const uint8_t *data, uint16_t length, uint16_t num_mods)
{
    if (length < num_mods * MOD_LIST_ENTRY_SIZE) {
        return -1;
    }

    mod_list_cleanup(moderation);

    if (num_mods == 0) {
        return 0;
    }

    uint8_t **tmp_list = (uint8_t **)calloc(num_mods, sizeof(uint8_t *));

    if (tmp_list == nullptr) {
        return -1;
    }

    uint16_t unpacked_len = 0;

    for (uint16_t i = 0; i < num_mods; ++i) {
        tmp_list[i] = (uint8_t *)malloc(sizeof(uint8_t) * MOD_LIST_ENTRY_SIZE);

        if (tmp_list[i] == nullptr) {
            free_uint8_t_pointer_array(tmp_list, i);
            return -1;
        }

        memcpy(tmp_list[i], &data[i * MOD_LIST_ENTRY_SIZE], MOD_LIST_ENTRY_SIZE);
        unpacked_len += MOD_LIST_ENTRY_SIZE;
    }

    moderation->mod_list = tmp_list;
    moderation->num_mods = num_mods;

    return unpacked_len;
}

void mod_list_pack(const Moderation *moderation, uint8_t *data)
{
    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        memcpy(&data[i * MOD_LIST_ENTRY_SIZE], moderation->mod_list[i], MOD_LIST_ENTRY_SIZE);
    }
}

void mod_list_get_data_hash(uint8_t *hash, const uint8_t *packed_mod_list, uint16_t length)
{
    crypto_sha256(hash, packed_mod_list, length);
}

bool mod_list_make_hash(const Moderation *moderation, uint8_t *hash)
{
    if (moderation->num_mods == 0) {
        memset(hash, 0, MOD_MODERATION_HASH_SIZE);
        return true;
    }

    const size_t data_buf_size = mod_list_packed_size(moderation);

    assert(data_buf_size > 0);

    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return false;
    }

    mod_list_pack(moderation, data);

    mod_list_get_data_hash(hash, data, data_buf_size);

    free(data);

    return true;
}

/**
 * Returns moderator list index for public_sig_key.
 * Returns -1 if key is not in the list.
 */
non_null()
static int mod_list_index_of_sig_pk(const Moderation *moderation, const uint8_t *public_sig_key)
{
    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], public_sig_key, SIG_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

bool mod_list_verify_sig_pk(const Moderation *moderation, const uint8_t *sig_pk)
{
    if (memcmp(moderation->founder_public_sig_key, sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
        return true;
    }

    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

bool mod_list_remove_index(Moderation *moderation, uint16_t index)
{
    if (index >= moderation->num_mods) {
        return false;
    }

    if ((moderation->num_mods - 1) == 0) {
        mod_list_cleanup(moderation);
        return true;
    }

    --moderation->num_mods;

    if (index != moderation->num_mods) {
        memcpy(moderation->mod_list[index], moderation->mod_list[moderation->num_mods],
               MOD_LIST_ENTRY_SIZE);
    }

    free(moderation->mod_list[moderation->num_mods]);
    moderation->mod_list[moderation->num_mods] = nullptr;

    uint8_t **tmp_list = (uint8_t **)realloc(moderation->mod_list, moderation->num_mods * sizeof(uint8_t *));

    if (tmp_list == nullptr) {
        return false;
    }

    moderation->mod_list = tmp_list;

    return true;
}

bool mod_list_remove_entry(Moderation *moderation, const uint8_t *public_sig_key)
{
    if (moderation->num_mods == 0) {
        return false;
    }

    const int idx = mod_list_index_of_sig_pk(moderation, public_sig_key);

    if (idx == -1) {
        return false;
    }

    assert(idx <= UINT16_MAX);

    return mod_list_remove_index(moderation, (uint16_t)idx);
}

bool mod_list_add_entry(Moderation *moderation, const uint8_t *mod_data)
{
    if (moderation->num_mods >= MOD_MAX_NUM_MODERATORS) {
        return false;
    }

    uint8_t **tmp_list = (uint8_t **)realloc(moderation->mod_list, (moderation->num_mods + 1) * sizeof(uint8_t *));

    if (tmp_list == nullptr) {
        return false;
    }

    moderation->mod_list = tmp_list;

    tmp_list[moderation->num_mods] = (uint8_t *)malloc(sizeof(uint8_t) * MOD_LIST_ENTRY_SIZE);

    if (tmp_list[moderation->num_mods] == nullptr) {
        return false;
    }

    memcpy(tmp_list[moderation->num_mods], mod_data, MOD_LIST_ENTRY_SIZE);
    ++moderation->num_mods;

    return true;
}

void mod_list_cleanup(Moderation *moderation)
{
    free_uint8_t_pointer_array(moderation->mod_list, moderation->num_mods);
    moderation->num_mods = 0;
    moderation->mod_list = nullptr;
}

uint16_t sanctions_creds_pack(const Mod_Sanction_Creds *creds, uint8_t *data)
{
    uint16_t packed_len = 0;

    net_pack_u32(data + packed_len, creds->version);
    packed_len += sizeof(uint32_t);
    memcpy(data + packed_len, creds->hash, MOD_SANCTION_HASH_SIZE);
    packed_len += MOD_SANCTION_HASH_SIZE;
    net_pack_u16(data + packed_len, creds->checksum);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, creds->sig_pk, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;
    memcpy(data + packed_len, creds->sig, SIGNATURE_SIZE);
    packed_len += SIGNATURE_SIZE;

    return packed_len;
}

uint16_t sanctions_list_packed_size(uint16_t num_sanctions)
{
    return MOD_SANCTION_PACKED_SIZE * num_sanctions;
}

int sanctions_list_pack(uint8_t *data, uint16_t length, const Mod_Sanction *sanctions, uint16_t num_sanctions,
                        const Mod_Sanction_Creds *creds)
{
    assert(sanctions != nullptr || num_sanctions == 0);
    assert(sanctions != nullptr || creds != nullptr);

    uint16_t packed_len = 0;

    for (uint16_t i = 0; i < num_sanctions; ++i) {
        if (packed_len + sizeof(uint8_t) + SIG_PUBLIC_KEY_SIZE + TIME_STAMP_SIZE > length) {
            return -1;
        }

        memcpy(data + packed_len, &sanctions[i].type, sizeof(uint8_t));
        packed_len += sizeof(uint8_t);
        memcpy(data + packed_len, sanctions[i].setter_public_sig_key, SIG_PUBLIC_KEY_SIZE);
        packed_len += SIG_PUBLIC_KEY_SIZE;
        net_pack_u64(data + packed_len, sanctions[i].time_set);
        packed_len += TIME_STAMP_SIZE;

        const uint8_t sanctions_type = sanctions[i].type;

        if (sanctions_type == SA_OBSERVER) {
            if (packed_len + ENC_PUBLIC_KEY_SIZE > length) {
                return -1;
            }

            memcpy(data + packed_len, sanctions[i].target_public_enc_key, ENC_PUBLIC_KEY_SIZE);
            packed_len += ENC_PUBLIC_KEY_SIZE;
        } else {
            return -1;
        }

        if (packed_len + SIGNATURE_SIZE > length) {
            return -1;
        }

        /* Signature must be packed last */
        memcpy(data + packed_len, sanctions[i].signature, SIGNATURE_SIZE);
        packed_len += SIGNATURE_SIZE;
    }

    if (creds == nullptr) {
        return packed_len;
    }

    if (length < packed_len || length - packed_len < MOD_SANCTIONS_CREDS_SIZE) {
        return -1;
    }

    const uint16_t cred_len = sanctions_creds_pack(creds, data + packed_len);

    if (cred_len != MOD_SANCTIONS_CREDS_SIZE) {
        return -1;
    }

    return (int)(packed_len + cred_len);
}

uint16_t sanctions_creds_unpack(Mod_Sanction_Creds *creds, const uint8_t *data)
{
    uint16_t len_processed = 0;

    net_unpack_u32(data + len_processed, &creds->version);
    len_processed += sizeof(uint32_t);
    memcpy(creds->hash, data + len_processed, MOD_SANCTION_HASH_SIZE);
    len_processed += MOD_SANCTION_HASH_SIZE;
    net_unpack_u16(data + len_processed, &creds->checksum);
    len_processed += sizeof(uint16_t);
    memcpy(creds->sig_pk, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;
    memcpy(creds->sig, data + len_processed, SIGNATURE_SIZE);
    len_processed += SIGNATURE_SIZE;

    return len_processed;
}

int sanctions_list_unpack(Mod_Sanction *sanctions, Mod_Sanction_Creds *creds, uint16_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len)
{
    uint16_t num = 0;
    uint16_t len_processed = 0;

    while (num < max_sanctions && num < MOD_MAX_NUM_SANCTIONS && len_processed < length) {
        if (len_processed + sizeof(uint8_t) + SIG_PUBLIC_KEY_SIZE + TIME_STAMP_SIZE > length) {
            return -1;
        }

        memcpy(&sanctions[num].type, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(sanctions[num].setter_public_sig_key, data + len_processed, SIG_PUBLIC_KEY_SIZE);
        len_processed += SIG_PUBLIC_KEY_SIZE;
        net_unpack_u64(data + len_processed, &sanctions[num].time_set);
        len_processed += TIME_STAMP_SIZE;

        if (sanctions[num].type == SA_OBSERVER) {
            if (len_processed + ENC_PUBLIC_KEY_SIZE > length) {
                return -1;
            }

            memcpy(sanctions[num].target_public_enc_key, data + len_processed, ENC_PUBLIC_KEY_SIZE);
            len_processed += ENC_PUBLIC_KEY_SIZE;
        } else {
            return -1;
        }

        if (len_processed + SIGNATURE_SIZE > length) {
            return -1;
        }

        memcpy(sanctions[num].signature, data + len_processed, SIGNATURE_SIZE);
        len_processed += SIGNATURE_SIZE;

        ++num;
    }

    if (length <= len_processed || length - len_processed < MOD_SANCTIONS_CREDS_SIZE) {
        if (length != len_processed) {
            return -1;
        }

        if (processed_data_len != nullptr) {
            *processed_data_len = len_processed;
        }

        return num;
    }

    const uint16_t creds_len = sanctions_creds_unpack(creds, data + len_processed);

    if (creds_len != MOD_SANCTIONS_CREDS_SIZE) {
        return -1;
    }

    if (processed_data_len != nullptr) {
        *processed_data_len = len_processed + creds_len;
    }

    return num;
}


/** @brief Creates a new sanction list hash and puts it in hash.
 *
 * The hash is derived from the signature of all entries plus the version number.
 * hash must have room for at least MOD_SANCTION_HASH_SIZE bytes.
 *
 * If num_sanctions is 0 the hash is zeroed.
 *
 * Return true on success.
 */
non_null(4) nullable(1)
static bool sanctions_list_make_hash(const Mod_Sanction *sanctions, uint32_t new_version, uint16_t num_sanctions,
                                    uint8_t *hash)
{
    if (num_sanctions == 0 || sanctions == nullptr) {
        memset(hash, 0, MOD_SANCTION_HASH_SIZE);
        return true;
    }

    const size_t sig_data_size = num_sanctions * SIGNATURE_SIZE;
    const size_t data_buf_size = sig_data_size + sizeof(uint32_t);

    // check for integer overflower
    if (data_buf_size < num_sanctions) {
        return false;
    }

    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return false;
    }

    for (uint16_t i = 0; i < num_sanctions; ++i) {
        memcpy(&data[i * SIGNATURE_SIZE], sanctions[i].signature, SIGNATURE_SIZE);
    }

    memcpy(&data[sig_data_size], &new_version, sizeof(uint32_t));
    crypto_sha256(hash, data, data_buf_size);

    free(data);

    return true;
}

/** @brief Verifies that sanction contains valid info and was assigned by a current mod or group founder.
 *
 * Returns true on success.
 */
non_null()
static bool sanctions_list_validate_entry(const Moderation *moderation, const Mod_Sanction *sanction)
{
    if (!mod_list_verify_sig_pk(moderation, sanction->setter_public_sig_key)) {
        return false;
    }

    if (sanction->type >= SA_INVALID) {
        return false;
    }

    if (sanction->time_set == 0) {
        return false;
    }

    uint8_t packed_data[MOD_SANCTION_PACKED_SIZE];
    const int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, 1, nullptr);

    if (packed_len <= (int) SIGNATURE_SIZE) {
        return false;
    }

    return crypto_signature_verify(sanction->signature, packed_data, packed_len - SIGNATURE_SIZE,
                                   sanction->setter_public_sig_key);
}

non_null()
static uint16_t sanctions_creds_get_checksum(const Mod_Sanction_Creds *creds)
{
    return data_checksum(creds->hash, sizeof(creds->hash));
}

non_null()
static void sanctions_creds_set_checksum(Mod_Sanction_Creds *creds)
{
    creds->checksum = sanctions_creds_get_checksum(creds);
}

bool sanctions_list_make_creds(Moderation *moderation)
{
    const Mod_Sanction_Creds old_creds = moderation->sanctions_creds;

    ++moderation->sanctions_creds.version;

    memcpy(moderation->sanctions_creds.sig_pk, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

    uint8_t hash[MOD_SANCTION_HASH_SIZE];

    if (!sanctions_list_make_hash(moderation->sanctions, moderation->sanctions_creds.version,
                                  moderation->num_sanctions, hash)) {
        moderation->sanctions_creds = old_creds;
        return false;
    }

    memcpy(moderation->sanctions_creds.hash, hash, MOD_SANCTION_HASH_SIZE);

    sanctions_creds_set_checksum(&moderation->sanctions_creds);

    if (!crypto_signature_create(moderation->sanctions_creds.sig, moderation->sanctions_creds.hash,
                                 MOD_SANCTION_HASH_SIZE, moderation->self_secret_sig_key)) {
        moderation->sanctions_creds = old_creds;
        return false;
    }

    return true;
}

/** @brief Validates sanction list credentials.
 *
 * Verifies that:
 * - the public signature key belongs to a mod or the founder
 * - the signature for the hash was made by the owner of the public signature key.
 * - the received hash matches our own hash of the new sanctions list
 * - the received checksum matches the received hash
 * - the new version is >= our current version
 *
 * Returns true on success.
 */
non_null(1, 3) nullable(2)
static bool sanctions_creds_validate(const Moderation *moderation, const Mod_Sanction *sanctions,
                                     const Mod_Sanction_Creds *creds, uint16_t num_sanctions)
{
    if (!mod_list_verify_sig_pk(moderation, creds->sig_pk)) {
        LOGGER_WARNING(moderation->log, "Invalid credentials signature pk");
        return false;
    }

    uint8_t hash[MOD_SANCTION_HASH_SIZE];

    if (!sanctions_list_make_hash(sanctions, creds->version, num_sanctions, hash)) {
        return false;
    }

    if (memcmp(hash, creds->hash, MOD_SANCTION_HASH_SIZE) != 0) {
        LOGGER_WARNING(moderation->log, "Invalid credentials hash");
        return false;
    }

    if (creds->checksum != sanctions_creds_get_checksum(creds)) {
        LOGGER_WARNING(moderation->log, "Invalid credentials checksum");
        return false;
    }

    if (moderation->shared_state_version > 0) {
        if ((creds->version < moderation->sanctions_creds.version)
                && !(creds->version == 0 && moderation->sanctions_creds.version == UINT32_MAX)) {
            LOGGER_WARNING(moderation->log, "Invalid version");
            return false;
        }
    }

    if (!crypto_signature_verify(creds->sig, hash, MOD_SANCTION_HASH_SIZE, creds->sig_pk)) {
        LOGGER_WARNING(moderation->log, "Invalid signature");
        return false;
    }

    return true;
}

bool sanctions_list_check_integrity(const Moderation *moderation, const Mod_Sanction_Creds *creds,
                                    const Mod_Sanction *sanctions, uint16_t num_sanctions)
{
    for (uint16_t i = 0; i < num_sanctions; ++i) {
        if (!sanctions_list_validate_entry(moderation, &sanctions[i])) {
            LOGGER_WARNING(moderation->log, "Invalid entry");
            return false;
        }
    }

    return sanctions_creds_validate(moderation, sanctions, creds, num_sanctions);
}

/** @brief Validates a sanctions list if credentials are supplied. If successful,
 *   or if no credentials are supplid, assigns new sanctions list and credentials
 *   to moderation object.
 *
 * @param moderation The moderation object being operated on.
 * @param new_sanctions The sanctions list to validate and assign to moderation object.
 * @param new_creds The new sanctions credentials to be assigned to moderation object.
 * @param num_sanctions The number of sanctions in the sanctions list.
 *
 * @retval false if sanctions credentials validation fails.
 */
non_null(1, 2) nullable(3)
static bool sanctions_apply_new(Moderation *moderation, Mod_Sanction *new_sanctions,
                                const Mod_Sanction_Creds *new_creds,
                                uint16_t num_sanctions)
{
    if (new_creds != nullptr) {
        if (!sanctions_creds_validate(moderation, new_sanctions, new_creds, num_sanctions)) {
            LOGGER_WARNING(moderation->log, "Failed to validate credentials");
            return false;
        }

        moderation->sanctions_creds = *new_creds;
    }

    sanctions_list_cleanup(moderation);
    moderation->sanctions = new_sanctions;
    moderation->num_sanctions = num_sanctions;

    return true;
}

/** @brief Returns a copy of the sanctions list. The caller is responsible for freeing the
 * memory returned by this function.
 */
non_null()
static Mod_Sanction *sanctions_list_copy(const Mod_Sanction *sanctions, uint16_t num_sanctions)
{
    Mod_Sanction *copy = (Mod_Sanction *)calloc(num_sanctions, sizeof(Mod_Sanction));

    if (copy == nullptr) {
        return nullptr;
    }

    memcpy(copy, sanctions, num_sanctions * sizeof(Mod_Sanction));

    return copy;
}

/** @brief Removes index-th sanction list entry.
 *
 * New credentials will be validated if creds is non-null.
 *
 * Returns true on success.
 */
non_null(1) nullable(3)
static bool sanctions_list_remove_index(Moderation *moderation, uint16_t index, const Mod_Sanction_Creds *creds)
{
    if (index >= moderation->num_sanctions) {
        return false;
    }

    const uint16_t new_num = moderation->num_sanctions - 1;

    if (new_num == 0) {
        if (creds != nullptr) {
            if (!sanctions_creds_validate(moderation, nullptr, creds, 0)) {
                return false;
            }

            moderation->sanctions_creds = *creds;
        }

        sanctions_list_cleanup(moderation);

        return true;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    Mod_Sanction *sanctions_copy = sanctions_list_copy(moderation->sanctions, moderation->num_sanctions);

    if (sanctions_copy == nullptr) {
        return false;
    }

    if (index != new_num) {
        sanctions_copy[index] = sanctions_copy[new_num];
    }

    Mod_Sanction *new_list = (Mod_Sanction *)realloc(sanctions_copy, new_num * sizeof(Mod_Sanction));

    if (new_list == nullptr) {
        free(sanctions_copy);
        return false;
    }

    if (!sanctions_apply_new(moderation, new_list, creds, new_num)) {
        free(new_list);
        return false;
    }

    return true;
}

bool sanctions_list_remove_observer(Moderation *moderation, const uint8_t *public_key,
                                    const Mod_Sanction_Creds *creds)
{
    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        const Mod_Sanction *curr_sanction = &moderation->sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(public_key, curr_sanction->target_public_enc_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            if (!sanctions_list_remove_index(moderation, i, creds)) {
                return false;
            }

            if (creds == nullptr) {
                return sanctions_list_make_creds(moderation);
            }

            return true;
        }
    }

    return false;
}

bool sanctions_list_is_observer(const Moderation *moderation, const uint8_t *public_key)
{
    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        const Mod_Sanction *curr_sanction = &moderation->sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(curr_sanction->target_public_enc_key, public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

bool sanctions_list_entry_exists(const Moderation *moderation, const Mod_Sanction *sanction)
{
    if (sanction->type == SA_OBSERVER) {
        return sanctions_list_is_observer(moderation, sanction->target_public_enc_key);
    }

    return false;
}

bool sanctions_list_add_entry(Moderation *moderation, const Mod_Sanction *sanction, const Mod_Sanction_Creds *creds)
{
    if (moderation->num_sanctions >= MOD_MAX_NUM_SANCTIONS) {
        LOGGER_WARNING(moderation->log, "num_sanctions %d exceeds maximum", moderation->num_sanctions);
        return false;
    }

    if (!sanctions_list_validate_entry(moderation, sanction)) {
        LOGGER_ERROR(moderation->log, "Failed to validate sanction");
        return false;
    }

    if (sanctions_list_entry_exists(moderation, sanction)) {
        LOGGER_WARNING(moderation->log, "Attempted to add duplicate sanction");
        return false;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    Mod_Sanction *sanctions_copy = nullptr;

    if (moderation->num_sanctions > 0) {
        sanctions_copy = sanctions_list_copy(moderation->sanctions, moderation->num_sanctions);

        if (sanctions_copy == nullptr) {
            return false;
        }
    }

    const uint16_t index = moderation->num_sanctions;
    Mod_Sanction *new_list = (Mod_Sanction *)realloc(sanctions_copy, (index + 1) * sizeof(Mod_Sanction));

    if (new_list == nullptr) {
        free(sanctions_copy);
        return false;
    }

    new_list[index] = *sanction;

    if (!sanctions_apply_new(moderation, new_list, creds, index + 1)) {
        free(new_list);
        return false;
    }

    return true;
}

/** @brief Signs packed sanction data.
 *
 * This function must be called by the owner of the entry's public_sig_key.
 *
 * Returns true on success.
 */
non_null()
static bool sanctions_list_sign_entry(const Moderation *moderation, Mod_Sanction *sanction)
{
    uint8_t packed_data[MOD_SANCTION_PACKED_SIZE];
    const int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, 1, nullptr);

    if (packed_len <= (int) SIGNATURE_SIZE) {
        LOGGER_ERROR(moderation->log, "Failed to pack sanctions list: %d", packed_len);
        return false;
    }

    return crypto_signature_create(sanction->signature, packed_data, packed_len - SIGNATURE_SIZE,
                                   moderation->self_secret_sig_key);
}

bool sanctions_list_make_entry(Moderation *moderation, const uint8_t *public_key, Mod_Sanction *sanction,
                               uint8_t type)
{
    *sanction = (Mod_Sanction) {
        0
    };

    if (type == SA_OBSERVER) {
        memcpy(sanction->target_public_enc_key, public_key, ENC_PUBLIC_KEY_SIZE);
    } else {
        LOGGER_ERROR(moderation->log, "Tried to create sanction with invalid type: %u", type);
        return false;
    }

    memcpy(sanction->setter_public_sig_key, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

    sanction->time_set = (uint64_t)time(nullptr);
    sanction->type = type;

    if (!sanctions_list_sign_entry(moderation, sanction)) {
        LOGGER_ERROR(moderation->log, "Failed to sign sanction");
        return false;
    }

    if (!sanctions_list_add_entry(moderation, sanction, nullptr)) {
        return false;
    }

    if (!sanctions_list_make_creds(moderation)) {
        LOGGER_ERROR(moderation->log, "Failed to make credentials for new sanction");
        return false;
    }

    return true;
}
uint16_t sanctions_list_replace_sig(Moderation *moderation, const uint8_t *public_sig_key)
{
    uint16_t count = 0;

    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        if (memcmp(moderation->sanctions[i].setter_public_sig_key, public_sig_key, SIG_PUBLIC_KEY_SIZE) != 0) {
            continue;
        }

        memcpy(moderation->sanctions[i].setter_public_sig_key, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

        if (!sanctions_list_sign_entry(moderation, &moderation->sanctions[i])) {
            LOGGER_ERROR(moderation->log, "Failed to sign sanction");
            continue;
        }

        ++count;
    }

    if (count > 0) {
        if (!sanctions_list_make_creds(moderation)) {
            return 0;
        }
    }

    return count;
}

void sanctions_list_cleanup(Moderation *moderation)
{
    if (moderation->sanctions != nullptr) {
        free(moderation->sanctions);
    }

    moderation->sanctions = nullptr;
    moderation->num_sanctions = 0;
}
