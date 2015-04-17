/**********GROUP CHAT FUNCTIONS: WARNING Group chats will be rewritten so this might change ************/

/* Set the callback for group invites.
 *
 *  Function(Tox *tox, int32_t friendnumber, uint8_t type, uint8_t *data, uint16_t length, void *userdata)
 *
 * data of length is what needs to be passed to join_groupchat().
 */
void tox_callback_group_invite(Tox *tox, void (*function)(Messenger *tox, int32_t, uint8_t, const uint8_t *, uint16_t,
                               void *), void *userdata)
{
    Messenger *m = tox;
    g_callback_group_invite(m->group_chat_object, function, userdata);
}

/* Set the callback for group messages.
 *
 *  Function(Tox *tox, int groupnumber, int peernumber, uint8_t * message, uint16_t length, void *userdata)
 */
void tox_callback_group_message(Tox *tox, void (*function)(Messenger *tox, int, int, const uint8_t *, uint16_t, void *),
                                void *userdata)
{
    Messenger *m = tox;
    g_callback_group_message(m->group_chat_object, function, userdata);
}

/* Set the callback for group actions.
 *
 *  Function(Tox *tox, int groupnumber, int peernumber, uint8_t * action, uint16_t length, void *userdata)
 */
void tox_callback_group_action(Tox *tox, void (*function)(Messenger *tox, int, int, const uint8_t *, uint16_t, void *),
                               void *userdata)
{
    Messenger *m = tox;
    g_callback_group_action(m->group_chat_object, function, userdata);
}

/* Set callback function for title changes.
 *
 * Function(Tox *tox, int groupnumber, int peernumber, uint8_t * title, uint8_t length, void *userdata)
 * if peernumber == -1, then author is unknown (e.g. initial joining the group)
 */
void tox_callback_group_title(Tox *tox, void (*function)(Messenger *tox, int, int, const uint8_t *, uint8_t,
                              void *), void *userdata)
{
    Messenger *m = tox;
    g_callback_group_title(m->group_chat_object, function, userdata);
}

/* Set callback function for peer name list changes.
 *
 * It gets called every time the name list changes(new peer/name, deleted peer)
 *  Function(Tox *tox, int groupnumber, void *userdata)
 */
void tox_callback_group_namelist_change(Tox *tox, void (*function)(Tox *tox, int, int, uint8_t, void *), void *userdata)
{
    Messenger *m = tox;
    g_callback_group_namelistchange(m->group_chat_object, function, userdata);
}

/* Creates a new groupchat and puts it in the chats array.
 *
 * return group number on success.
 * return -1 on failure.
 */
int tox_add_groupchat(Tox *tox)
{
    Messenger *m = tox;
    return add_groupchat(m->group_chat_object, GROUPCHAT_TYPE_TEXT);
}

/* Delete a groupchat from the chats array.
 *
 * return 0 on success.
 * return -1 if failure.
 */
int tox_del_groupchat(Tox *tox, int groupnumber)
{
    Messenger *m = tox;
    return del_groupchat(m->group_chat_object, groupnumber);
}

/* Copy the name of peernumber who is in groupnumber to name.
 * name must be at least MAX_NICK_BYTES long.
 *
 * return length of name if success
 * return -1 if failure
 */
int tox_group_peername(const Tox *tox, int groupnumber, int peernumber, uint8_t *name)
{
    const Messenger *m = tox;
    return group_peername(m->group_chat_object, groupnumber, peernumber, name);
}

/* Copy the public key of peernumber who is in groupnumber to public_key.
 * public_key must be crypto_box_PUBLICKEYBYTES long.
 *
 * returns 0 on success
 * returns -1 on failure
 */
int tox_group_peer_pubkey(const Tox *tox, int groupnumber, int peernumber, uint8_t *public_key)
{
    const Messenger *m = tox;
    return group_peer_pubkey(m->group_chat_object, groupnumber, peernumber, public_key);
}

/* invite friendnumber to groupnumber
 * return 0 on success
 * return -1 on failure
 */
int tox_invite_friend(Tox *tox, int32_t friendnumber, int groupnumber)
{
    Messenger *m = tox;
    return invite_friend(m->group_chat_object, friendnumber, groupnumber);
}

/* Join a group (you need to have been invited first.) using data of length obtained
 * in the group invite callback.
 *
 * returns group number on success
 * returns -1 on failure.
 */
int tox_join_groupchat(Tox *tox, int32_t friendnumber, const uint8_t *data, uint16_t length)
{
    Messenger *m = tox;
    return join_groupchat(m->group_chat_object, friendnumber, GROUPCHAT_TYPE_TEXT, data, length);
}

/* send a group message
 * return 0 on success
 * return -1 on failure
 */
int tox_group_message_send(Tox *tox, int groupnumber, const uint8_t *message, uint16_t length)
{
    Messenger *m = tox;
    return group_message_send(m->group_chat_object, groupnumber, message, length);
}

/* send a group action
 * return 0 on success
 * return -1 on failure
 */
int tox_group_action_send(Tox *tox, int groupnumber, const uint8_t *action, uint16_t length)
{
    Messenger *m = tox;
    return group_action_send(m->group_chat_object, groupnumber, action, length);
}

/* set the group's title, limited to MAX_NAME_LENGTH
 * return 0 on success
 * return -1 on failure
 */
int tox_group_set_title(Tox *tox, int groupnumber, const uint8_t *title, uint8_t length)
{
    Messenger *m = tox;
    return group_title_send(m->group_chat_object, groupnumber, title, length);
}

/* Get group title from groupnumber and put it in title.
 * title needs to be a valid memory location with a max_length size of at least MAX_NAME_LENGTH (128) bytes.
 *
 *  return length of copied title if success.
 *  return -1 if failure.
 */
int tox_group_get_title(Tox *tox, int groupnumber, uint8_t *title, uint32_t max_length)
{
    Messenger *m = tox;
    return group_title_get(m->group_chat_object, groupnumber, title, max_length);
}

/* Check if the current peernumber corresponds to ours.
 *
 * return 1 if the peernumber corresponds to ours.
 * return 0 on failure.
 */
unsigned int tox_group_peernumber_is_ours(const Tox *tox, int groupnumber, int peernumber)
{
    const Messenger *m = tox;
    return group_peernumber_is_ours(m->group_chat_object, groupnumber, peernumber);
}

/* Return the number of peers in the group chat on success.
 * return -1 on failure
 */
int tox_group_number_peers(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    return group_number_peers(m->group_chat_object, groupnumber);
}

/* List all the peers in the group chat.
 *
 * Copies the names of the peers to the name[length][MAX_NICK_BYTES] array.
 *
 * Copies the lengths of the names to lengths[length]
 *
 * returns the number of peers on success.
 *
 * return -1 on failure.
 */
int tox_group_get_names(const Tox *tox, int groupnumber, uint8_t names[][TOX_MAX_NAME_LENGTH], uint16_t lengths[],
                        uint16_t length)
{
    const Messenger *m = tox;
    return group_names(m->group_chat_object, groupnumber, names, lengths, length);
}

/* Return the number of chats in the instance m.
 * You should use this to determine how much memory to allocate
 * for copy_chatlist. */
uint32_t tox_count_chatlist(const Tox *tox)
{
    const Messenger *m = tox;
    return count_chatlist(m->group_chat_object);
}

/* Copy a list of valid chat IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size. */
uint32_t tox_get_chatlist(const Tox *tox, int32_t *out_list, uint32_t list_size)
{
    const Messenger *m = tox;
    return copy_chatlist(m->group_chat_object, out_list, list_size);
}

/* return the type of groupchat (TOX_GROUPCHAT_TYPE_) that groupnumber is.
 *
 * return -1 on failure.
 * return type on success.
 */
int tox_group_get_type(const Tox *tox, int groupnumber)
{
    const Messenger *m = tox;
    return group_get_type(m->group_chat_object, groupnumber);
}
