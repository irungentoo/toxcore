/* tox.c
 *
 * The Tox public API.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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

#define TOX_DEFINED
typedef struct Messenger Tox;
#include "tox_group.h"

#include "Messenger.h"
#include "group.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

/**********GROUP CHAT FUNCTIONS: WARNING Group chats will be rewritten so this might change ************/

/* Set the callback for group invites.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t type, uint8_t *data, uint16_t length, void *userdata)
 *
 * data of length is what needs to be passed to join_groupchat().
 */
void tox_callback_conference_invite(Tox *tox, tox_conference_invite_cb *callback, void *user_data)
{
    Messenger *m = tox;
    g_callback_group_invite(
        m->group_chat_object,
        (void (*)(Messenger * m, uint32_t, int, const uint8_t *, size_t, void *))callback,
        user_data);
}

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int peernumber, uint8_t * message, uint16_t length, void *userdata)
 */
void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback, void *user_data)
{
    Messenger *m = tox;
    g_callback_group_message(
        m->group_chat_object,
        (void (*)(Messenger * m, uint32_t, uint32_t, int, const uint8_t *, size_t, void *))callback,
        user_data);
}

/* Set callback function for title changes.
 *
 * Function(Tox *tox, int groupnumber, int peernumber, uint8_t * title, uint8_t length, void *userdata)
 * if peernumber == -1, then author is unknown (e.g. initial joining the group)
 */
void tox_callback_conference_title(Tox *tox, tox_conference_title_cb *callback, void *user_data)
{
    Messenger *m = tox;
    g_callback_group_title(m->group_chat_object, callback, user_data);
}

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, void *userdata)
 */
void tox_callback_conference_namelist_change(Tox *tox, tox_conference_namelist_change_cb *callback, void *user_data)
{
    Messenger *m = tox;
    g_callback_group_namelistchange(
        m->group_chat_object,
        (void (*)(struct Messenger *, int, int, uint8_t, void *))callback,
        user_data);
}

/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
uint32_t tox_conference_new(Tox *tox, TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;
    int res = add_groupchat(m->group_chat_object, GROUPCHAT_TYPE_TEXT);

    if (res == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_FAILURE);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_OK);
    return res;
}

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
bool tox_conference_delete(Tox *tox, uint32_t group_number, TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;
    int res = del_groupchat(m->group_chat_object, group_number);

    if (res == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_FAILURE);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_OK);
    return true;
}

size_t tox_conference_peer_get_name_size(
    const Tox *tox, uint32_t group_number, uint32_t peer_number, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    int res = group_peername_size(m->group_chat_object, group_number, peer_number);

    if (res == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_FAILURE);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_OK);
    return res;
}

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
bool tox_conference_peer_get_name(const Tox *tox, uint32_t group_number, uint32_t peer_number, uint8_t *name,
                                  TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_peername(m->group_chat_object, group_number, peer_number, name);
}

/* Copy the public key of peernumber who is in groupnumber to public_key.
 * public_key must be crypto_box_PUBLICKEYBYTES long.
 *
 * returns 0 on success
 * returns -1 on failure
 */
bool tox_conference_peer_get_public_key(const Tox *tox, uint32_t group_number, uint32_t peer_number,
                                        uint8_t *public_key, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_peer_pubkey(m->group_chat_object, group_number, peer_number, public_key);
}

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
bool tox_conference_invite(Tox *tox, uint32_t friendnumber, uint32_t group_number, TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;
    return invite_friend(m->group_chat_object, friendnumber, group_number);
}

/* Join a group (you need to have been invited first.) using data of length obtained
 * in the group invite callback.
 *
 * returns group number on success
 * returns -1 on failure.
 */
uint32_t tox_conference_join(Tox *tox, uint32_t friendnumber, const uint8_t *data, size_t length,
                             TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;
    return join_groupchat(m->group_chat_object, friendnumber, GROUPCHAT_TYPE_TEXT, data, length);
}

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
bool tox_conference_send_message(Tox *tox, uint32_t groupnumber, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;

    if (type == TOX_MESSAGE_TYPE_NORMAL) {
        return group_message_send(m->group_chat_object, groupnumber, message, length);
    } else {
        return group_action_send(m->group_chat_object, groupnumber, message, length);
    }
}

/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 on failure
 */
bool tox_conference_set_title(Tox *tox, uint32_t groupnumber, const uint8_t *title, size_t length,
                              TOX_ERR_CONFERENCE *error)
{
    Messenger *m = tox;
    return group_title_send(m->group_chat_object, groupnumber, title, length);
}

size_t tox_conference_get_title_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_title_get_size(m->group_chat_object, groupnumber);
}

/* Get group title from groupnumber and put it in title.
 * title needs to be a valid memory location with a max_length size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of copied title if success.
 *  return -1 if failure.
 */
bool tox_conference_get_title(const Tox *tox, uint32_t groupnumber, uint8_t *title, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_title_get(m->group_chat_object, groupnumber, title);
}

/* Check if the current peernumber corresponds to ours.
 *
 * return 1 if the peernumber corresponds to ours.
 * return 0 on failure.
 */
bool tox_conference_peer_number_is_ours(const Tox *tox, uint32_t groupnumber, uint32_t peernumber)
{
    const Messenger *m = tox;
    return group_peernumber_is_ours(m->group_chat_object, groupnumber, peernumber);
}

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
uint32_t tox_conference_peer_count(const Tox *tox, uint32_t groupnumber, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_number_peers(m->group_chat_object, groupnumber);
}

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
size_t tox_conference_get_chatlist_size(const Tox *tox)
{
    const Messenger *m = tox;
    return count_chatlist(m->group_chat_object);
}

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
void tox_conference_get_chatlist(const Tox *tox, uint32_t *out_list)
{
    const Messenger *m = tox;
    size_t list_size = tox_conference_get_chatlist_size(tox);
    copy_chatlist(m->group_chat_object, out_list, list_size);
}

/* return the type of groupchat (TOX_GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
TOX_CONFERENCE_TYPE tox_conference_get_type(const Tox *tox, uint32_t groupnumber, TOX_ERR_CONFERENCE *error)
{
    const Messenger *m = tox;
    return group_get_type(m->group_chat_object, groupnumber);
}
