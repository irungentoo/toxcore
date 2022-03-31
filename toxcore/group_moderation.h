/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_MODERATION_H
#define C_TOXCORE_TOXCORE_GROUP_MODERATION_H

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MOD_MODERATION_HASH_SIZE CRYPTO_SHA256_SIZE
#define MOD_LIST_ENTRY_SIZE SIG_PUBLIC_KEY_SIZE
#define MOD_SANCTION_HASH_SIZE CRYPTO_SHA256_SIZE

#define TIME_STAMP_SIZE sizeof(uint64_t)

/* The packed size of a Mod_Sanction_Creds */
#define MOD_SANCTIONS_CREDS_SIZE (sizeof(uint32_t) + MOD_SANCTION_HASH_SIZE + sizeof(uint16_t) +\
                                       SIG_PUBLIC_KEY_SIZE + SIGNATURE_SIZE)

/* The packed size of a Mod_Sanction */
#define MOD_SANCTION_PACKED_SIZE (SIG_PUBLIC_KEY_SIZE + TIME_STAMP_SIZE + 1 + ENC_PUBLIC_KEY_SIZE + SIGNATURE_SIZE)

/* The max size of a groupchat packet with 100 bytes reserved for header data */
#define MAX_PACKET_SIZE_NO_HEADERS 49900

/* These values must take into account the maximum allowed packet size and headers. */
#define MOD_MAX_NUM_MODERATORS (((MAX_PACKET_SIZE_NO_HEADERS) / (MOD_LIST_ENTRY_SIZE)))
#define MOD_MAX_NUM_SANCTIONS  (((MAX_PACKET_SIZE_NO_HEADERS - (MOD_SANCTIONS_CREDS_SIZE)) / (MOD_SANCTION_PACKED_SIZE)))

typedef enum Mod_Sanction_Type {
    SA_OBSERVER = 0x00,
    SA_INVALID  = 0x01,
} Mod_Sanction_Type;

typedef struct Mod_Sanction_Creds {
    uint32_t    version;
    uint8_t     hash[MOD_SANCTION_HASH_SIZE];    // hash of all sanctions list signatures + version
    uint16_t    checksum;  // a sum of the hash
    uint8_t     sig_pk[SIG_PUBLIC_KEY_SIZE];    // Last mod to have modified the sanctions list
    uint8_t     sig[SIGNATURE_SIZE];    // signature of hash, signed by sig_pk
} Mod_Sanction_Creds;

/** Holds data pertaining to a peer who has been sanctioned. */
typedef struct Mod_Sanction {
    uint8_t     setter_public_sig_key[SIG_PUBLIC_KEY_SIZE];

    // TODO(Jfreegman): This timestamp can potentially be used to track a user across
    // different group chats if they're a moderator and set many sanctions across the
    // different groups. This should be addressed in the future.
    uint64_t    time_set;

    uint8_t     type;
    uint8_t     target_public_enc_key[ENC_PUBLIC_KEY_SIZE];

    /* Signature of all above packed data signed by the owner of public_sig_key */
    uint8_t     signature[SIGNATURE_SIZE];
} Mod_Sanction;

typedef struct Moderation {
    const       Logger *log;

    Mod_Sanction *sanctions;
    uint16_t    num_sanctions;

    Mod_Sanction_Creds sanctions_creds;

    uint8_t     **mod_list;  // array of public signature keys of all the mods
    uint16_t    num_mods;

    // copies from parent/sibling chat/shared state objects
    uint8_t     founder_public_sig_key[SIG_PUBLIC_KEY_SIZE];
    uint8_t     self_public_sig_key[SIG_PUBLIC_KEY_SIZE];
    uint8_t     self_secret_sig_key[SIG_SECRET_KEY_SIZE];
    uint32_t    shared_state_version;
} Moderation;

/** @brief Returns the size in bytes of the packed moderation list. */
non_null()
uint16_t mod_list_packed_size(const Moderation *moderation);

/** @brief Unpacks data into the moderator list.
 *
 * @param data should contain num_mods entries of size MOD_LIST_ENTRY_SIZE.
 *
 * Returns length of unpacked data on success.
 * Returns -1 on failure.
 */
non_null()
int mod_list_unpack(Moderation *moderation, const uint8_t *data, uint16_t length, uint16_t num_mods);

/** @brief Packs moderator list into data.
 * @param data must have room for the number of bytes returned by `mod_list_packed_size`.
 */
non_null()
void mod_list_pack(const Moderation *moderation, uint8_t *data);

/** @brief Creates a new moderator list hash and puts it in `hash`.
 *
 * @param hash must have room for at least MOD_MODERATION_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 *
 * Returns true on sucess.
 */
non_null()
bool mod_list_make_hash(const Moderation *moderation, uint8_t *hash);

/** @brief Puts a sha256 hash of `packed_mod_list` of `length` bytes in `hash`.
 *
 * @param hash must have room for at least MOD_MODERATION_HASH_SIZE bytes.
 */
non_null()
void mod_list_get_data_hash(uint8_t *hash, const uint8_t *packed_mod_list, uint16_t length);

/** @brief Removes moderator at index-th position in the moderator list.
 *
 * Returns true on success.
 */
non_null()
bool mod_list_remove_index(Moderation *moderation, uint16_t index);

/** @brief Removes public_sig_key from the moderator list.
 *
 * Returns true on success.
 */
non_null()
bool mod_list_remove_entry(Moderation *moderation, const uint8_t *public_sig_key);

/** @brief Adds a mod to the moderator list.
 *
 * @param mod_data must be MOD_LIST_ENTRY_SIZE bytes.
 *
 * Returns true on success.
 */
non_null()
bool mod_list_add_entry(Moderation *moderation, const uint8_t *mod_data);

/** @return true if the public signature key belongs to a moderator or the founder */
non_null()
bool mod_list_verify_sig_pk(const Moderation *moderation, const uint8_t *sig_pk);

/** @brief Frees all memory associated with the moderator list and sets num_mods to 0. */
nullable(1)
void mod_list_cleanup(Moderation *moderation);

/** @brief Returns the size in bytes of num_sanctions packed sanctions. */
uint16_t sanctions_list_packed_size(uint16_t num_sanctions);

/** @brief Packs sanctions into data. Additionally packs the sanctions credentials into creds.
 *
 * @param data The byte array being packed. Must have room for the number of bytes returned
 *   by `sanctions_list_packed_size`.
 * @param length The size of the byte array.
 * @param sanctions The sanctions list.
 * @param num_sanctions The number of sanctions in the sanctions list. This value must be the same
 *   value used when calling `sanctions_list_packed_size`.
 * @param creds The credentials object to fill.
 *
 * @retval The length of packed data on success.
 * @retval -1 on failure.
 */
non_null(1) nullable(3, 5)
int sanctions_list_pack(uint8_t *data, uint16_t length, const Mod_Sanction *sanctions, uint16_t num_sanctions,
                        const Mod_Sanction_Creds *creds);

/** @brief Unpacks sanctions and new sanctions credentials.
 *
 * @param sanctions The sanctions array the sanctions data is unpacked into.
 * @param creds The creds object the creds data is unpacked into.
 * @param max_sanctions The maximum number of sanctions that the sanctions array can hold.
 * @param data The packed data array.
 * @param length The size of the packed data.
 * @param processed_data_len If non-null, will contain the number of processed bytes on success.
 *
 * @retval The number of unpacked entries on success.
 * @retval -1 on failure.
 */
non_null(1, 2, 4) nullable(6)
int sanctions_list_unpack(Mod_Sanction *sanctions, Mod_Sanction_Creds *creds, uint16_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len);

/** @brief Packs sanction list credentials into data.
 *
 * @param data must have room for MOD_SANCTIONS_CREDS_SIZE bytes.
 *
 * Returns length of packed data.
 */
non_null()
uint16_t sanctions_creds_pack(const Mod_Sanction_Creds *creds, uint8_t *data);

/** @brief Unpacks sanctions credentials into creds from data.
 *
 * @param data must have room for MOD_SANCTIONS_CREDS_SIZE bytes.
 *
 * Returns the length of the data processed.
 */
non_null()
uint16_t sanctions_creds_unpack(Mod_Sanction_Creds *creds, const uint8_t *data);

/** @brief Updates sanction list credentials.
 *
 * Increment version, replace sig_pk with your own, update hash to reflect new
 * sanction list, and sign new hash signature.
 *
 * Returns true on success.
 */
non_null()
bool sanctions_list_make_creds(Moderation *moderation);

/** @brief Validates all sanctions list entries as well as the list itself.
 *
 * Returns true if all entries are valid.
 * Returns false if one or more entries are invalid.
 */
non_null()
bool sanctions_list_check_integrity(const Moderation *moderation, const Mod_Sanction_Creds *creds,
                                    const Mod_Sanction *sanctions, uint16_t num_sanctions);

/** @brief Adds an entry to the sanctions list.
 *
 * The entry is first validated and the resulting new sanction list is
 * compared against the new credentials.
 *
 * Entries must be unique.
 *
 * Returns true on success.
 */
non_null(1, 2) nullable(3)
bool sanctions_list_add_entry(Moderation *moderation, const Mod_Sanction *sanction, const Mod_Sanction_Creds *creds);

/** @brief Creates a new sanction entry for `public_key` where type is one of Mod_Sanction_Type.
 *
 * New entry is signed and placed in the sanctions list.
 *
 * Returns true on success.
 */
non_null()
bool sanctions_list_make_entry(Moderation *moderation, const uint8_t *public_key, Mod_Sanction *sanction,
                               uint8_t type);

/** @return true if public key is in the observer list. */
non_null()
bool sanctions_list_is_observer(const Moderation *moderation, const uint8_t *public_key);

/** @return true if sanction already exists in the sanctions list. */
non_null()
bool sanctions_list_entry_exists(const Moderation *moderation, const Mod_Sanction *sanction);

/** @brief Removes observer entry for public key from sanction list.
 *
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 * Returns false on failure or if entry was not found.
 */
non_null(1, 2) nullable(3)
bool sanctions_list_remove_observer(Moderation *moderation, const uint8_t *public_key,
                                    const Mod_Sanction_Creds *creds);

/** @brief Replaces all sanctions list signatures made by public_sig_key with the caller's.
 *
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
non_null()
uint16_t sanctions_list_replace_sig(Moderation *moderation, const uint8_t *public_sig_key);

non_null()
void sanctions_list_cleanup(Moderation *moderation);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_GROUP_MODERATION_H
