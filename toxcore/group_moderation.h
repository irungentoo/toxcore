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
int mod_list_get_index(const GC_Chat *chat, uint32_t peernumber);

/* Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(GC_Chat *chat, size_t index);

/* Removes peernumber from the moderator list and assigns their new role.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_peer(GC_Chat *chat, uint32_t peernumber, uint8_t role);

/* Adds peernumber to the moderator list and assigns role.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 * Returns -2 if the mod list is full.
 */
int mod_list_add_peer(GC_Chat *chat, uint32_t peernumber);

/* Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(GC_Chat *chat);

#endif /* GROUP_MODERATION_H */
