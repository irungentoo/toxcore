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

    chat->mod_list = tmp_list;
    chat->num_mods = num_mods;

    return unpacked_len;
}

/* Packs moderator list into data.
 * data must have room for num_mods * SIG_PUBLIC_KEY bytes..
 */
void mod_list_pack(const GC_Chat *chat, uint8_t *data)
{
    uint16_t i;

    for (i = 0; i < chat->num_mods && i < MAX_GC_MODERATORS; ++i)
        memcpy(&data[i * GC_MOD_LIST_ENTRY_SIZE], chat->mod_list[i], GC_MOD_LIST_ENTRY_SIZE);
}

/* Creates a new moderator list hash and puts it in hash.
 * hash must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 */
void mod_list_make_hash(GC_Chat *chat, uint8_t *hash)
{
    if (chat->num_mods == 0) {
        memset(hash, 0, GC_MOD_LIST_HASH_SIZE);
        return;
    }

    uint8_t data[chat->num_mods * GC_MOD_LIST_ENTRY_SIZE];
    mod_list_pack(chat, data);
    crypto_hash_sha256(hash, data, sizeof(data));
}

/* Returns moderator list index for peernumber.
 * Returns -1 if peernumber is not in the list.
 */
int mod_list_get_index(const GC_Chat *chat, uint32_t peernumber)
{
    uint16_t i;

    for (i = 0; i < chat->num_mods; ++i) {
        if (memcmp(chat->mod_list[i], SIG_PK(chat->gcc[peernumber].addr.public_key), SIG_PUBLIC_KEY) == 0)
            return i;
    }

    return -1;
}

/* Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(GC_Chat *chat, size_t index)
{
    if (chat->num_mods == 0)
        return -1;

    --chat->num_mods;

    if (chat->num_mods == 0) {
        free(chat->mod_list);
        chat->mod_list = NULL;
        return 0;
    }

    if (index != chat->num_mods)
        memcpy(chat->mod_list[index], chat->mod_list[chat->num_mods], GC_MOD_LIST_ENTRY_SIZE);

    free(chat->mod_list[chat->num_mods]);
    chat->mod_list[chat->num_mods] = NULL;

    uint8_t **tmp_list = realloc(chat->mod_list, sizeof(uint8_t *) * (chat->num_mods));
    chat->mod_list = tmp_list;

    if (chat->mod_list == NULL) {
        chat->num_mods = 0;
        return -1;
    }

    return 0;
}

/* Removes peernumber from the moderator list and assigns their new role.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_peer(GC_Chat *chat, uint32_t peernumber, uint8_t role)
{
    if (chat->num_mods == 0)
        return -1;

    if (role <= GR_MODERATOR)
        return -1;

    int idx = mod_list_get_index(chat, peernumber);

    if (idx == -1)
        return -1;

    chat->group[peernumber].role = role;

    return mod_list_remove_index(chat, idx);
}

/* Adds peernumber to the moderator list and assigns role.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if the mod list is full.
 */
int mod_list_add_peer(GC_Chat *chat, uint32_t peernumber)
{
    if (chat->num_mods >= MAX_GC_MODERATORS)
        return -2;

    uint8_t **tmp_list = realloc(chat->mod_list, sizeof(uint8_t *) * (chat->num_mods + 1));

    if (tmp_list == NULL)
        return -1;

    tmp_list[chat->num_mods] = malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

    if (tmp_list[chat->num_mods] == NULL)
        return -1;

    chat->group[peernumber].role = GR_MODERATOR;
    memcpy(tmp_list[chat->num_mods], SIG_PK(chat->gcc[peernumber].addr.public_key), GC_MOD_LIST_ENTRY_SIZE);
    chat->mod_list = tmp_list;
    ++chat->num_mods;

    return 0;
}

/* Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(GC_Chat *chat)
{
    free_uint8_t_pointer_array(chat->mod_list, chat->num_mods);
    chat->num_mods = 0;
    chat->mod_list = NULL;
}
