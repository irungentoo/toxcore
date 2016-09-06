/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_MODERATION_H
#define GROUP_MODERATION_H

#define MAX_GC_SANCTIONS 200
#define GC_SANCTIONS_CREDENTIALS_SIZE (sizeof(uint32_t) + GC_MODERATION_HASH_SIZE + SIG_PUBLIC_KEY + SIGNATURE_SIZE)

typedef enum Group_Sanction_Type {
    SA_BAN,
    SA_OBSERVER,
    SA_INVALID,
} Group_Sanction_Type;

struct GC_Ban {
    IP_Port     ip_port;
    uint8_t     nick[MAX_GC_NICK_SIZE];
    uint16_t    nick_len;
    uint32_t    id;
};

typedef union GC_Sanction_Info {
    struct GC_Ban ban_info;    /* Used if type is SA_BAN */
    uint8_t       target_pk[ENC_PUBLIC_KEY];    /* Used if type is SA_OBSERVER */
} GC_Sanction_Info;

/* Holds data pertaining to a peer who has been banned or demoted to observer. */
struct GC_Sanction {
    uint8_t     public_sig_key[SIG_PUBLIC_KEY];
    uint64_t    time_set;

    uint8_t     type;
    GC_Sanction_Info info;

    /* Signature of all above packed data signed by the owner of public_sig_key */
    uint8_t     signature[SIGNATURE_SIZE];
};

/* Unpacks data into the moderator list.
 * data should contain num_mods entries of size GC_MOD_LIST_ENTRY_SIZE.
 *
 * Returns length of unpacked data on success.
 * Returns -1 on failure.
 */
int mod_list_unpack(GC_Chat *chat, const uint8_t *data, uint32_t length, uint32_t num_mods);

/* Packs moderator list into data.
 * data must have room for `num_mods * GC_MOD_LIST_ENTRY_SIZE` bytes.
 */
void mod_list_pack(const GC_Chat *chat, uint8_t *data);

/* Creates a new moderator list hash and puts it in hash.
 * hash must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 */
void mod_list_make_hash(GC_Chat *chat, uint8_t *hash);

/* Returns moderator list index for public_sig_key.
 * Returns -1 if key is not in the list.
 */
int mod_list_index_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key);

/* Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(GC_Chat *chat, size_t index);

/* Removes public_sig_key from the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_entry(GC_Chat *chat, const uint8_t *public_sig_key);

/* Adds a mod to the moderator list. mod_data must be GC_MOD_LIST_ENTRY_SIZE bytes.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_add_entry(GC_Chat *chat, const uint8_t *mod_data);

/* Returns true if the public signature key belongs to a moderator or the founder */
bool mod_list_verify_sig_pk(const GC_Chat *chat, const uint8_t *sig_pk);

/* Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(GC_Chat *chat);

/* Packs num_sanctions sanctions into data of maxlength length. Additionally packs the
 * sanctions list credentials into creds if creds is non-NULL.
 *
 * Returns length of packed data on success.
 * Returns -1 on failure.
 */
int sanctions_list_pack(uint8_t *data, uint16_t length, struct GC_Sanction *sanctions,
                        struct GC_Sanction_Creds *creds, uint32_t num_sanctions);

/* Unpack max_sanctions sanctions from data into sanctions, and unpacks credentials into creds.
 * Put the length of the data processed in processed_data_len.
 *
 * Returns number of unpacked entries on success.
 * Returns -1 on failure.
 */
int sanctions_list_unpack(struct GC_Sanction *sanctions, struct GC_Sanction_Creds *creds, uint32_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len);

/* Packs sanction list credentials into data.
 * data must have room for GC_SANCTIONS_CREDENTIALS_SIZE bytes.
 *
 * Returns length of packed data.
 */
uint16_t sanctions_creds_pack(struct GC_Sanction_Creds *creds, uint8_t *data, uint16_t length);

/* Unpacks sanctions credentials into creds from data.
 * data must have room for GC_SANCTIONS_CREDENTIALS_SIZE bytes.
 *
 * Returns the length of the data processed.
 */
uint16_t sanctions_creds_unpack(struct GC_Sanction_Creds *creds, const uint8_t *data, uint16_t length);

/* Updates sanction list credentials: increment version, replace sig_pk with your own,
 * update hash to reflect new sanction list, and sign new hash signature.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_creds(GC_Chat *chat);

/* Validates all sanctions list entries as well as the list itself.
 *
 * Returns 0 if all entries are valid.
 * Returns -1 if one or more entries are invalid.
 */
int sanctions_list_check_integrity(const GC_Chat *chat, struct GC_Sanction_Creds *creds,
                                   struct GC_Sanction *sanctions, uint32_t num_sanctions);

/* Adds an entry to the sanctions list. The entry is first validated and the resulting
 * new sanction list is compared against the new credentials.
 *
 * Entries must be unique.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_add_entry(GC_Chat *chat, struct GC_Sanction *sanction, struct GC_Sanction_Creds *creds);

/* Creates a new sanction entry for peernumber where type is one GROUP_SANCTION_TYPE.
 * New entry is signed and placed in the sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_entry(GC_Chat *chat, uint32_t peernumber, struct GC_Sanction *sanction, uint8_t type);

/* Returns true if public key is in the observer list. */
bool sanctions_list_is_observer(const GC_Chat *chat, const uint8_t *public_key);

/* Removes observer entry for public key from sanction list.
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found.
 */
int sanctions_list_remove_observer(GC_Chat *chat, const uint8_t *public_key, struct GC_Sanction_Creds *creds);

/* Removes ban entry with ban_id from sanction list.
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found
 */
int sanctions_list_remove_ban(GC_Chat *chat, uint32_t ban_id, struct GC_Sanction_Creds *creds);

/* Replaces all sanctions list signatures made by public_sig_key with the caller's.
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
uint32_t sanctions_list_replace_sig(GC_Chat *chat, const uint8_t *public_sig_key);

/* Creates a new sanction list hash and puts it in hash.
 *
 * The hash is derived from the signature of all entries plus the version number.
 * hash must have room for at least GC_MODERATION_HASH_SIZE bytes.
 *
 * If num_sanctions is 0 the hash is zeroed.
 */
void sanctions_list_make_hash(struct GC_Sanction *sanctions, uint32_t new_version, uint32_t num_sanctions,
                              uint8_t *hash);

void sanctions_list_cleanup(GC_Chat *chat);



/* Ban list queries */


/* Returns true if the IP address is in the ban list. */
bool sanctions_list_ip_banned(const GC_Chat *chat, IP_Port *ip_port);

/* Returns the number of sanctions list entries that are of type SA_BAN */
uint32_t sanctions_list_num_banned(const GC_Chat *chat);

/* Fills list with all valid ban ID's. */
void sanctions_list_get_ban_list(const GC_Chat *chat, uint32_t *list);

/* Returns the nick length of the ban entry associted with ban_id on success.
 * Returns 0 if ban_id does not exist.
 */
uint16_t sanctions_list_get_ban_nick_length(const GC_Chat *chat, uint32_t ban_id);

/* Copies the nick associated with ban_id to nick.
 *
 * Returns 0 on success.
 * Returns -1 if ban_id does not exist.
 */
int sanctions_list_get_ban_nick(const GC_Chat *chat, uint32_t ban_id, uint8_t *nick);

/* Returns a timestamp indicating when the ban designated by ban_id was set.
 * Returns 0 if ban_id does not exist.
 */
uint64_t sanctions_list_get_ban_time_set(const GC_Chat *chat, uint32_t ban_id);

#endif /* GROUP_MODERATION_H */
