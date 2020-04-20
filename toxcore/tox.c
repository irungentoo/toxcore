/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * The Tox public API.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef __cplusplus
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#endif

#include "tox.h"
#include "tox_private.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Messenger.h"
#include "group.h"
#include "group_chats.h"
#include "group_moderation.h"
#include "logger.h"
#include "mono_time.h"

#include "../toxencryptsave/defines.h"

#define SET_ERROR_PARAMETER(param, x) do { if (param) { *param = x; } } while (0)

#if TOX_HASH_LENGTH != CRYPTO_SHA256_SIZE
#error "TOX_HASH_LENGTH is assumed to be equal to CRYPTO_SHA256_SIZE"
#endif

#if FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error "FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE"
#endif

#if TOX_FILE_ID_LENGTH != CRYPTO_SYMMETRIC_KEY_SIZE
#error "TOX_FILE_ID_LENGTH is assumed to be equal to CRYPTO_SYMMETRIC_KEY_SIZE"
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error "TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH"
#endif

#if TOX_PUBLIC_KEY_SIZE != CRYPTO_PUBLIC_KEY_SIZE
#error "TOX_PUBLIC_KEY_SIZE is assumed to be equal to CRYPTO_PUBLIC_KEY_SIZE"
#endif

#if TOX_SECRET_KEY_SIZE != CRYPTO_SECRET_KEY_SIZE
#error "TOX_SECRET_KEY_SIZE is assumed to be equal to CRYPTO_SECRET_KEY_SIZE"
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error "TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH"
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error "TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH"
#endif

struct Tox {
    // XXX: Messenger *must* be the first member, because toxav casts its
    // `Tox *` to `Messenger **`.
    Messenger *m;
    Mono_Time *mono_time;
    pthread_mutex_t *mutex;
    void *non_const_user_data;

    tox_self_connection_status_cb *self_connection_status_callback;
    tox_friend_name_cb *friend_name_callback;
    tox_friend_status_message_cb *friend_status_message_callback;
    tox_friend_status_cb *friend_status_callback;
    tox_friend_connection_status_cb *friend_connection_status_callback;
    tox_friend_typing_cb *friend_typing_callback;
    tox_friend_read_receipt_cb *friend_read_receipt_callback;
    tox_friend_request_cb *friend_request_callback;
    tox_friend_message_cb *friend_message_callback;
    tox_file_recv_control_cb *file_recv_control_callback;
    tox_file_chunk_request_cb *file_chunk_request_callback;
    tox_file_recv_cb *file_recv_callback;
    tox_file_recv_chunk_cb *file_recv_chunk_callback;
    tox_conference_invite_cb *conference_invite_callback;
    tox_conference_connected_cb *conference_connected_callback;
    tox_conference_message_cb *conference_message_callback;
    tox_conference_title_cb *conference_title_callback;
    tox_conference_peer_name_cb *conference_peer_name_callback;
    tox_conference_peer_list_changed_cb *conference_peer_list_changed_callback;
    tox_friend_lossy_packet_cb *friend_lossy_packet_callback_per_pktid[UINT8_MAX + 1];
    tox_friend_lossless_packet_cb *friend_lossless_packet_callback_per_pktid[UINT8_MAX + 1];
    tox_group_peer_name_cb *group_peer_name_callback;
    tox_group_peer_status_cb *group_peer_status_callback;
    tox_group_topic_cb *group_topic_callback;
    tox_group_privacy_state_cb *group_privacy_state_callback;
    tox_group_peer_limit_cb *group_peer_limit_callback;
    tox_group_password_cb *group_password_callback;
    tox_group_message_cb *group_message_callback;
    tox_group_private_message_cb *group_private_message_callback;
    tox_group_custom_packet_cb *group_custom_packet_callback;
    tox_group_invite_cb *group_invite_callback;
    tox_group_peer_join_cb *group_peer_join_callback;
    tox_group_peer_exit_cb *group_peer_exit_callback;
    tox_group_self_join_cb *group_self_join_callback;
    tox_group_join_fail_cb *group_join_fail_callback;
    tox_group_moderation_cb *group_moderation_callback;

    void *toxav_object; // workaround to store a ToxAV object (setter and getter functions are available)
};

static void lock(const Tox *tox)
{
    if (tox->mutex != nullptr) {
        pthread_mutex_lock(tox->mutex);
    }
}

static void unlock(const Tox *tox)
{
    if (tox->mutex != nullptr) {
        pthread_mutex_unlock(tox->mutex);
    }
}

struct Tox_Userdata {
    Tox *tox;
    void *user_data;
};

static void tox_self_connection_status_handler(Messenger *m, unsigned int connection_status, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->self_connection_status_callback != nullptr) {
        tox_data->tox->self_connection_status_callback(tox_data->tox, (Tox_Connection)connection_status, tox_data->user_data);
    }
}

static void tox_friend_name_handler(Messenger *m, uint32_t friend_number, const uint8_t *name, size_t length,
                                    void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_name_callback != nullptr) {
        tox_data->tox->friend_name_callback(tox_data->tox, friend_number, name, length, tox_data->user_data);
    }
}

static void tox_friend_status_message_handler(Messenger *m, uint32_t friend_number, const uint8_t *message,
        size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_status_message_callback != nullptr) {
        tox_data->tox->friend_status_message_callback(tox_data->tox, friend_number, message, length, tox_data->user_data);
    }
}

static void tox_friend_status_handler(Messenger *m, uint32_t friend_number, unsigned int status, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_status_callback != nullptr) {
        tox_data->tox->friend_status_callback(tox_data->tox, friend_number, (Tox_User_Status)status, tox_data->user_data);
    }
}

static void tox_friend_connection_status_handler(Messenger *m, uint32_t friend_number, unsigned int connection_status,
        void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_connection_status_callback != nullptr) {
        tox_data->tox->friend_connection_status_callback(tox_data->tox, friend_number, (Tox_Connection)connection_status,
                tox_data->user_data);
    }
}

static void tox_friend_typing_handler(Messenger *m, uint32_t friend_number, bool is_typing, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_typing_callback != nullptr) {
        tox_data->tox->friend_typing_callback(tox_data->tox, friend_number, is_typing, tox_data->user_data);
    }
}

static void tox_friend_read_receipt_handler(Messenger *m, uint32_t friend_number, uint32_t message_id, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_read_receipt_callback != nullptr) {
        tox_data->tox->friend_read_receipt_callback(tox_data->tox, friend_number, message_id, tox_data->user_data);
    }
}

static void tox_friend_request_handler(Messenger *m, const uint8_t *public_key, const uint8_t *message, size_t length,
                                       void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_request_callback != nullptr) {
        tox_data->tox->friend_request_callback(tox_data->tox, public_key, message, length, tox_data->user_data);
    }
}

static void tox_friend_message_handler(Messenger *m, uint32_t friend_number, unsigned int type, const uint8_t *message,
                                       size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_message_callback != nullptr) {
        tox_data->tox->friend_message_callback(tox_data->tox, friend_number, (Tox_Message_Type)type, message, length,
                                               tox_data->user_data);
    }
}

static void tox_file_recv_control_handler(Messenger *m, uint32_t friend_number, uint32_t file_number,
        unsigned int control, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->file_recv_control_callback != nullptr) {
        tox_data->tox->file_recv_control_callback(tox_data->tox, friend_number, file_number, (Tox_File_Control)control,
                tox_data->user_data);
    }
}

static void tox_file_chunk_request_handler(Messenger *m, uint32_t friend_number, uint32_t file_number,
        uint64_t position, size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->file_chunk_request_callback != nullptr) {
        tox_data->tox->file_chunk_request_callback(tox_data->tox, friend_number, file_number, position, length,
                tox_data->user_data);
    }
}

static void tox_file_recv_handler(Messenger *m, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                                  uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->file_recv_callback != nullptr) {
        tox_data->tox->file_recv_callback(tox_data->tox, friend_number, file_number, kind, file_size, filename, filename_length,
                                          tox_data->user_data);
    }
}

static void tox_file_recv_chunk_handler(Messenger *m, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                        const uint8_t *data, size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->file_recv_chunk_callback != nullptr) {
        tox_data->tox->file_recv_chunk_callback(tox_data->tox, friend_number, file_number, position, data, length,
                                                tox_data->user_data);
    }
}

static void tox_conference_invite_handler(Messenger *m, uint32_t friend_number, int type, const uint8_t *cookie,
        size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_invite_callback != nullptr) {
        tox_data->tox->conference_invite_callback(tox_data->tox, friend_number, (Tox_Conference_Type)type, cookie, length,
                tox_data->user_data);
    }
}

static void tox_conference_connected_handler(Messenger *m, uint32_t conference_number, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_connected_callback != nullptr) {
        tox_data->tox->conference_connected_callback(tox_data->tox, conference_number, tox_data->user_data);
    }
}

static void tox_conference_message_handler(Messenger *m, uint32_t conference_number, uint32_t peer_number, int type,
        const uint8_t *message, size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_message_callback != nullptr) {
        tox_data->tox->conference_message_callback(tox_data->tox, conference_number, peer_number, (Tox_Message_Type)type,
                message, length, tox_data->user_data);
    }
}

static void tox_conference_title_handler(Messenger *m, uint32_t conference_number, uint32_t peer_number,
        const uint8_t *title, size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_title_callback != nullptr) {
        tox_data->tox->conference_title_callback(tox_data->tox, conference_number, peer_number, title, length,
                tox_data->user_data);
    }
}

static void tox_conference_peer_name_handler(Messenger *m, uint32_t conference_number, uint32_t peer_number,
        const uint8_t *name, size_t length, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_peer_name_callback != nullptr) {
        tox_data->tox->conference_peer_name_callback(tox_data->tox, conference_number, peer_number, name, length,
                tox_data->user_data);
    }
}

static void tox_conference_peer_list_changed_handler(Messenger *m, uint32_t conference_number, void *user_data)
{
    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->conference_peer_list_changed_callback != nullptr) {
        tox_data->tox->conference_peer_list_changed_callback(tox_data->tox, conference_number, tox_data->user_data);
    }
}

static void tox_friend_lossy_packet_handler(Messenger *m, uint32_t friend_number, uint8_t packet_id,
        const uint8_t *data, size_t length, void *user_data)
{
    assert(data != nullptr);
    assert(length > 0);

    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_lossy_packet_callback_per_pktid[packet_id] != nullptr) {
        tox_data->tox->friend_lossy_packet_callback_per_pktid[packet_id](tox_data->tox, friend_number, data, length,
                tox_data->user_data);
    }
}

static void tox_friend_lossless_packet_handler(Messenger *m, uint32_t friend_number, uint8_t packet_id,
        const uint8_t *data, size_t length, void *user_data)
{
    assert(data != nullptr);
    assert(length > 0);

    struct Tox_Userdata *tox_data = (struct Tox_Userdata *)user_data;

    if (tox_data->tox->friend_lossless_packet_callback_per_pktid[packet_id] != nullptr) {
        tox_data->tox->friend_lossless_packet_callback_per_pktid[packet_id](tox_data->tox, friend_number, data, length,
                tox_data->user_data);
    }
}

#ifndef VANILLA_NACL
static void tox_group_peer_name_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, const uint8_t *name,
                                        size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_peer_name_callback != nullptr) {
        tox->group_peer_name_callback(tox, groupnumber, peer_id, name, length, tox->non_const_user_data);
    }
}

static void tox_group_peer_status_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, unsigned int status,
        void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_peer_status_callback != nullptr) {
        tox->group_peer_status_callback(tox, groupnumber, peer_id, (Tox_User_Status)status, tox->non_const_user_data);
    }
}

static void tox_group_topic_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic,
                                    size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_topic_callback != nullptr) {
        tox->group_topic_callback(tox, groupnumber, peer_id, topic, length, tox->non_const_user_data);
    }
}

static void tox_group_privacy_state_handler(Messenger *m, uint32_t groupnumber, unsigned int privacy_state,
        void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_privacy_state_callback != nullptr) {
        tox->group_privacy_state_callback(tox, groupnumber, (Tox_Group_Privacy_State)privacy_state, tox->non_const_user_data);
    }
}

static void tox_group_peer_limit_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_limit, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_peer_limit_callback != nullptr) {
        tox->group_peer_limit_callback(tox, groupnumber, peer_limit, tox->non_const_user_data);
    }
}

static void tox_group_password_handler(Messenger *m, uint32_t groupnumber, const uint8_t *password, size_t length,
                                       void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_password_callback != nullptr) {
        tox->group_password_callback(tox, groupnumber, password, length, tox->non_const_user_data);
    }
}

static void tox_group_message_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, unsigned int type,
                                      const uint8_t *message, size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_message_callback != nullptr) {
        tox->group_message_callback(tox, groupnumber, peer_id, (Tox_Message_Type)type, message, length,
                                    tox->non_const_user_data);
    }
}

static void tox_group_private_message_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id,
        const uint8_t *message, size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_private_message_callback != nullptr) {
        tox->group_private_message_callback(tox, groupnumber, peer_id, message, length, tox->non_const_user_data);
    }
}

static void tox_group_custom_packet_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, const uint8_t *data,
        size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_custom_packet_callback != nullptr) {
        tox->group_custom_packet_callback(tox, groupnumber, peer_id, data, length, tox->non_const_user_data);
    }
}

static void tox_group_invite_handler(Messenger *m, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                     void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_invite_callback != nullptr) {
        tox->group_invite_callback(tox, friend_number, invite_data, length, tox->non_const_user_data);
    }
}

static void tox_group_peer_join_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_peer_join_callback != nullptr) {
        tox->group_peer_join_callback(tox, groupnumber, peer_id, tox->non_const_user_data);
    }
}

static void tox_group_peer_exit_handler(Messenger *m, uint32_t groupnumber, uint32_t peer_id,
                                        const uint8_t *part_message, size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_peer_exit_callback != nullptr) {
        tox->group_peer_exit_callback(tox, groupnumber, peer_id, part_message, length, tox->non_const_user_data);
    }
}

static void tox_group_self_join_handler(Messenger *m, uint32_t groupnumber, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_self_join_callback != nullptr) {
        tox->group_self_join_callback(tox, groupnumber, tox->non_const_user_data);
    }
}

static void tox_group_join_fail_handler(Messenger *m, uint32_t groupnumber, unsigned int fail_type, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_join_fail_callback != nullptr) {
        tox->group_join_fail_callback(tox, groupnumber, (Tox_Group_Join_Fail)fail_type, tox->non_const_user_data);
    }
}

static void tox_group_moderation_handler(Messenger *m, uint32_t groupnumber, uint32_t source_peer_number,
        uint32_t target_peer_number, unsigned int mod_type, void *user_data)
{
    Tox *tox = (Tox *)user_data;

    if (tox->group_moderation_callback != nullptr) {
        tox->group_moderation_callback(tox, groupnumber, source_peer_number, target_peer_number, (Tox_Group_Mod_Event)mod_type,
                                       tox->non_const_user_data);
    }
}
#endif

bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    return TOX_VERSION_IS_API_COMPATIBLE(major, minor, patch);
}

static State_Load_Status state_load_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    const Tox *tox = (const Tox *)outer;
    State_Load_Status status = STATE_LOAD_STATUS_CONTINUE;

    if (messenger_load_state_section(tox->m, data, length, type, &status)
            || conferences_load_state_section(tox->m->conferences_object, data, length, type, &status)) {
        return status;
    }

    if (type == STATE_TYPE_END) {
        if (length != 0) {
            return STATE_LOAD_STATUS_ERROR;
        }

        return STATE_LOAD_STATUS_END;
    }

    LOGGER_ERROR(tox->m->log, "Load state: contains unrecognized part (len %u, type %u)",
                 length, type);

    return STATE_LOAD_STATUS_CONTINUE;
}

/* Load tox from data of size length. */
static int tox_load(Tox *tox, const uint8_t *data, uint32_t length)
{
    uint32_t data32[2];
    const uint32_t cookie_len = sizeof(data32);

    if (length < cookie_len) {
        return -1;
    }

    memcpy(data32, data, sizeof(uint32_t));
    lendian_bytes_to_host32(data32 + 1, data + sizeof(uint32_t));

    if (data32[0] != 0 || data32[1] != STATE_COOKIE_GLOBAL) {
        return -1;
    }

    return state_load(tox->m->log, state_load_callback, tox, data + cookie_len,
                      length - cookie_len, STATE_COOKIE_TYPE);
}


Tox *tox_new(const struct Tox_Options *options, Tox_Err_New *error)
{
    Tox *tox = (Tox *)calloc(1, sizeof(Tox));

    if (tox == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        return nullptr;
    }

    Messenger_Options m_options = {0};

    bool load_savedata_sk = false, load_savedata_tox = false;

    struct Tox_Options *default_options = nullptr;

    if (options == nullptr) {
        Tox_Err_Options_New err;
        default_options = tox_options_new(&err);

        switch (err) {
            case TOX_ERR_OPTIONS_NEW_OK:
                break;

            case TOX_ERR_OPTIONS_NEW_MALLOC:
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
                free(tox);
                return nullptr;
        }
    }

    const struct Tox_Options *const opts = options != nullptr ? options : default_options;
    assert(opts != nullptr);

    if (tox_options_get_savedata_type(opts) != TOX_SAVEDATA_TYPE_NONE) {
        if (tox_options_get_savedata_data(opts) == nullptr || tox_options_get_savedata_length(opts) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }
    }

    if (tox_options_get_savedata_type(opts) == TOX_SAVEDATA_TYPE_SECRET_KEY) {
        if (tox_options_get_savedata_length(opts) != TOX_SECRET_KEY_SIZE) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }

        load_savedata_sk = true;
    } else if (tox_options_get_savedata_type(opts) == TOX_SAVEDATA_TYPE_TOX_SAVE) {
        if (tox_options_get_savedata_length(opts) < TOX_ENC_SAVE_MAGIC_LENGTH) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }

        if (crypto_memcmp(tox_options_get_savedata_data(opts), TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }

        load_savedata_tox = true;
    }

    m_options.ipv6enabled = tox_options_get_ipv6_enabled(opts);
    m_options.udp_disabled = !tox_options_get_udp_enabled(opts);
    m_options.port_range[0] = tox_options_get_start_port(opts);
    m_options.port_range[1] = tox_options_get_end_port(opts);
    m_options.tcp_server_port = tox_options_get_tcp_port(opts);
    m_options.hole_punching_enabled = tox_options_get_hole_punching_enabled(opts);
    m_options.local_discovery_enabled = tox_options_get_local_discovery_enabled(opts);

    m_options.log_callback = (logger_cb *)tox_options_get_log_callback(opts);
    m_options.log_context = tox;
    m_options.log_user_data = tox_options_get_log_user_data(opts);

    switch (tox_options_get_proxy_type(opts)) {
        case TOX_PROXY_TYPE_HTTP:
            m_options.proxy_info.proxy_type = TCP_PROXY_HTTP;
            break;

        case TOX_PROXY_TYPE_SOCKS5:
            m_options.proxy_info.proxy_type = TCP_PROXY_SOCKS5;
            break;

        case TOX_PROXY_TYPE_NONE:
            m_options.proxy_info.proxy_type = TCP_PROXY_NONE;
            break;

        default:
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_TYPE);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
    }

    if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
        if (tox_options_get_proxy_port(opts) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }

        ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

        if (m_options.ipv6enabled) {
            m_options.proxy_info.ip_port.ip.family = net_family_unspec;
        }

        if (addr_resolve_or_parse_ip(tox_options_get_proxy_host(opts), &m_options.proxy_info.ip_port.ip, nullptr) == 0) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
            // TODO(irungentoo): TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }

        m_options.proxy_info.ip_port.port = net_htons(tox_options_get_proxy_port(opts));
    }

    tox->mono_time = mono_time_new();

    if (tox->mono_time == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        tox_options_free(default_options);
        free(tox);
        return nullptr;
    }

    if (tox_options_get_experimental_thread_safety(opts)) {
        tox->mutex = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));

        if (tox->mutex == nullptr) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
            tox_options_free(default_options);
            free(tox);
            return nullptr;
        }


        pthread_mutexattr_t attr;

        pthread_mutexattr_init(&attr);
        pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(tox->mutex, &attr);
    } else {
        tox->mutex = nullptr;
    }

    lock(tox);

    unsigned int m_error;
    tox->m = new_messenger(tox->mono_time, &m_options, &m_error);

    // TODO(iphydf): Clarify this code, check for NULL before new_groupchats, so
    // new_groupchats can assume m is non-NULL.
    if (!new_groupchats(tox->mono_time, tox->m)) {
        kill_messenger(tox->m);

        if (m_error == MESSENGER_ERROR_PORT) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else if (m_error == MESSENGER_ERROR_TCP_SERVER) {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PORT_ALLOC);
        } else {
            SET_ERROR_PARAMETER(error, TOX_ERR_NEW_MALLOC);
        }

        mono_time_free(tox->mono_time);
        tox_options_free(default_options);
        unlock(tox);

        if (tox->mutex != nullptr) {
            pthread_mutex_destroy(tox->mutex);
        }

        free(tox->mutex);
        free(tox);
        return nullptr;
    }

    if (load_savedata_tox
            && tox_load(tox, tox_options_get_savedata_data(opts), tox_options_get_savedata_length(opts)) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else if (load_savedata_sk) {
        load_secret_key(tox->m->net_crypto, tox_options_get_savedata_data(opts));
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

    m_callback_namechange(tox->m, tox_friend_name_handler);
    m_callback_core_connection(tox->m, tox_self_connection_status_handler);
    m_callback_statusmessage(tox->m, tox_friend_status_message_handler);
    m_callback_userstatus(tox->m, tox_friend_status_handler);
    m_callback_connectionstatus(tox->m, tox_friend_connection_status_handler);
    m_callback_typingchange(tox->m, tox_friend_typing_handler);
    m_callback_read_receipt(tox->m, tox_friend_read_receipt_handler);
    m_callback_friendrequest(tox->m, tox_friend_request_handler);
    m_callback_friendmessage(tox->m, tox_friend_message_handler);
    callback_file_control(tox->m, tox_file_recv_control_handler);
    callback_file_reqchunk(tox->m, tox_file_chunk_request_handler);
    callback_file_sendrequest(tox->m, tox_file_recv_handler);
    callback_file_data(tox->m, tox_file_recv_chunk_handler);
    g_callback_group_invite(tox->m->conferences_object, tox_conference_invite_handler);
    g_callback_group_connected(tox->m->conferences_object, tox_conference_connected_handler);
    g_callback_group_message(tox->m->conferences_object, tox_conference_message_handler);
    g_callback_group_title(tox->m->conferences_object, tox_conference_title_handler);
    g_callback_peer_name(tox->m->conferences_object, tox_conference_peer_name_handler);
    g_callback_peer_list_changed(tox->m->conferences_object, tox_conference_peer_list_changed_handler);
    custom_lossy_packet_registerhandler(tox->m, tox_friend_lossy_packet_handler);
    custom_lossless_packet_registerhandler(tox->m, tox_friend_lossless_packet_handler);

#ifndef VANILLA_NACL
    m_callback_group_invite(tox->m, tox_group_invite_handler, tox);
    gc_callback_message(tox->m, tox_group_message_handler, tox);
    gc_callback_private_message(tox->m, tox_group_private_message_handler, tox);
    gc_callback_custom_packet(tox->m, tox_group_custom_packet_handler, tox);
    gc_callback_moderation(tox->m, tox_group_moderation_handler, tox);
    gc_callback_nick_change(tox->m, tox_group_peer_name_handler, tox);
    gc_callback_status_change(tox->m, tox_group_peer_status_handler, tox);
    gc_callback_topic_change(tox->m, tox_group_topic_handler, tox);
    gc_callback_privacy_state(tox->m, tox_group_privacy_state_handler, tox);
    gc_callback_peer_limit(tox->m, tox_group_peer_limit_handler, tox);
    gc_callback_password(tox->m, tox_group_password_handler, tox);
    gc_callback_peer_join(tox->m, tox_group_peer_join_handler, tox);
    gc_callback_peer_exit(tox->m, tox_group_peer_exit_handler, tox);
    gc_callback_self_join(tox->m, tox_group_self_join_handler, tox);
    gc_callback_rejected(tox->m, tox_group_join_fail_handler, tox);
#endif

    tox_options_free(default_options);

    unlock(tox);
    return tox;
}

void tox_kill(Tox *tox)
{
    if (tox == nullptr) {
        return;
    }

    lock(tox);
    LOGGER_ASSERT(tox->m->log, tox->m->msi_packet == nullptr, "Attempted to kill tox while toxav is still alive");
    kill_groupchats(tox->m->conferences_object);
    kill_messenger(tox->m);
    mono_time_free(tox->mono_time);
    unlock(tox);

    if (tox->mutex != nullptr) {
        pthread_mutex_destroy(tox->mutex);
        free(tox->mutex);
    }

    free(tox);
}

static uint32_t end_size(void)
{
    return 2 * sizeof(uint32_t);
}

static void end_save(uint8_t *data)
{
    state_write_section_header(data, STATE_COOKIE_TYPE, 0, STATE_TYPE_END);
}

size_t tox_get_savedata_size(const Tox *tox)
{
    lock(tox);
    size_t ret = 2 * sizeof(uint32_t)
                 + messenger_size(tox->m)
                 + conferences_size(tox->m->conferences_object)
                 + end_size();
    unlock(tox);
    return ret;
}

void tox_get_savedata(const Tox *tox, uint8_t *savedata)
{
    if (savedata == nullptr) {
        return;
    }

    memset(savedata, 0, tox_get_savedata_size(tox));

    lock(tox);

    const uint32_t size32 = sizeof(uint32_t);

    // write cookie
    memset(savedata, 0, size32);
    savedata += size32;
    host_to_lendian_bytes32(savedata, STATE_COOKIE_GLOBAL);
    savedata += size32;

    savedata = messenger_save(tox->m, savedata);
    savedata = conferences_save(tox->m->conferences_object, savedata);
    end_save(savedata);

    unlock(tox);
}

bool tox_bootstrap(Tox *tox, const char *host, uint16_t port, const uint8_t *public_key, Tox_Err_Bootstrap *error)
{
    if (!host || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    const int32_t count = net_getipport(host, &root, TOX_SOCK_DGRAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    lock(tox);

    for (i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        onion_add_bs_path_node(tox->m->onion_c, root[i], public_key);
        dht_bootstrap(tox->m->dht, root[i], public_key);
    }

    unlock(tox);

    net_freeipport(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

bool tox_add_tcp_relay(Tox *tox, const char *host, uint16_t port, const uint8_t *public_key,
                       Tox_Err_Bootstrap *error)
{
    if (!host || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    IP_Port *root;

    int32_t count = net_getipport(host, &root, TOX_SOCK_STREAM);

    if (count == -1) {
        net_freeipport(root);
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    unsigned int i;

    lock(tox);

    for (i = 0; i < count; ++i) {
        root[i].port = net_htons(port);

        add_tcp_relay(tox->m->net_crypto, root[i], public_key);
    }

    unlock(tox);

    net_freeipport(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
    return 0;
}

Tox_Connection tox_self_get_connection_status(const Tox *tox)
{
    lock(tox);
    const unsigned int ret = onion_connection_status(tox->m->onion_c);
    unlock(tox);

    if (ret == 2) {
        return TOX_CONNECTION_UDP;
    }

    if (ret == 1) {
        return TOX_CONNECTION_TCP;
    }

    return TOX_CONNECTION_NONE;
}


void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback)
{
    tox->self_connection_status_callback = callback;
}

uint32_t tox_iteration_interval(const Tox *tox)
{
    lock(tox);
    uint32_t ret = messenger_run_interval(tox->m);
    unlock(tox);
    return ret;
}

void tox_iterate(Tox *tox, void *user_data)
{
    lock(tox);

    mono_time_update(tox->mono_time);

    struct Tox_Userdata tox_data = { tox, user_data };
    tox->non_const_user_data = user_data;
    do_messenger(tox->m, &tox_data);
    do_groupchats(tox->m->conferences_object, &tox_data);

    unlock(tox);
}

void tox_self_get_address(const Tox *tox, uint8_t *address)
{
    if (address) {
        lock(tox);
        getaddress(tox->m, address);
        unlock(tox);
    }
}

void tox_self_set_nospam(Tox *tox, uint32_t nospam)
{
    lock(tox);
    set_nospam(tox->m->fr, net_htonl(nospam));
    unlock(tox);
}

uint32_t tox_self_get_nospam(const Tox *tox)
{
    lock(tox);
    uint32_t ret = net_ntohl(get_nospam(tox->m->fr));
    unlock(tox);
    return ret;
}

void tox_self_get_public_key(const Tox *tox, uint8_t *public_key)
{
    if (public_key) {
        lock(tox);
        memcpy(public_key, nc_get_self_public_key(tox->m->net_crypto), CRYPTO_PUBLIC_KEY_SIZE);
        unlock(tox);
    }
}

void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key)
{
    if (secret_key) {
        lock(tox);
        memcpy(secret_key, nc_get_self_secret_key(tox->m->net_crypto), CRYPTO_SECRET_KEY_SIZE);
        unlock(tox);
    }
}

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, Tox_Err_Set_Info *error)
{
    if (!name && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    lock(tox);

    if (setname(tox->m, name, length) == 0) {
        // TODO(irungentoo): function to set different per group names?
        send_name_all_groups(tox->m->conferences_object);
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        unlock(tox);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    unlock(tox);
    return 0;
}

size_t tox_self_get_name_size(const Tox *tox)
{
    lock(tox);
    size_t ret = m_get_self_name_size(tox->m);
    unlock(tox);
    return ret;
}

void tox_self_get_name(const Tox *tox, uint8_t *name)
{
    if (name) {
        lock(tox);
        getself_name(tox->m, name);
        unlock(tox);
    }
}

bool tox_self_set_status_message(Tox *tox, const uint8_t *status_message, size_t length, Tox_Err_Set_Info *error)
{
    if (!status_message && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    lock(tox);

    if (m_set_statusmessage(tox->m, status_message, length) == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        unlock(tox);
        return 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
    unlock(tox);
    return 0;
}

size_t tox_self_get_status_message_size(const Tox *tox)
{
    lock(tox);
    size_t ret = m_get_self_statusmessage_size(tox->m);
    unlock(tox);
    return ret;
}

void tox_self_get_status_message(const Tox *tox, uint8_t *status_message)
{
    if (status_message) {
        lock(tox);
        m_copy_self_statusmessage(tox->m, status_message);
        unlock(tox);
    }
}

void tox_self_set_status(Tox *tox, Tox_User_Status status)
{
    lock(tox);
    m_set_userstatus(tox->m, status);
    unlock(tox);
}

Tox_User_Status tox_self_get_status(const Tox *tox)
{
    lock(tox);
    const uint8_t status = m_get_self_userstatus(tox->m);
    unlock(tox);
    return (Tox_User_Status)status;
}

static void set_friend_error(const Logger *log, int32_t ret, Tox_Err_Friend_Add *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_MALLOC);
            break;

        default:
            /* can't happen */
            LOGGER_FATAL(log, "impossible: unknown friend-add error");
            break;
    }
}

uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        Tox_Err_Friend_Add *error)
{
    if (!address || !message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    lock(tox);
    const int32_t ret = m_addfriend(tox->m, address, message, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        unlock(tox);
        return ret;
    }

    set_friend_error(tox->m->log, ret, error);
    unlock(tox);
    return UINT32_MAX;
}

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, Tox_Err_Friend_Add *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    lock(tox);
    const int32_t ret = m_addfriend_norequest(tox->m, public_key);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        unlock(tox);
        return ret;
    }

    set_friend_error(tox->m->log, ret, error);
    unlock(tox);
    return UINT32_MAX;
}

bool tox_friend_delete(Tox *tox, uint32_t friend_number, Tox_Err_Friend_Delete *error)
{
    lock(tox);
    const int ret = m_delfriend(tox->m, friend_number);
    unlock(tox);

    // TODO(irungentoo): handle if realloc fails?
    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_OK);
    return 1;
}

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, Tox_Err_Friend_By_Public_Key *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL);
        return UINT32_MAX;
    }

    lock(tox);
    const int32_t ret = getfriend_id(tox->m, public_key);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    return ret;
}

bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               Tox_Err_Friend_Get_Public_Key *error)
{
    if (!public_key) {
        return 0;
    }

    lock(tox);

    if (get_real_pk(tox->m, friend_number, public_key) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);
        unlock(tox);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);
    unlock(tox);
    return 1;
}

bool tox_friend_exists(const Tox *tox, uint32_t friend_number)
{
    lock(tox);
    bool ret = m_friend_exists(tox->m, friend_number);
    unlock(tox);
    return ret;
}

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Get_Last_Online *error)
{
    lock(tox);
    const uint64_t timestamp = m_get_last_online(tox->m, friend_number);
    unlock(tox);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND);
        return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    return timestamp;
}

size_t tox_self_get_friend_list_size(const Tox *tox)
{
    lock(tox);
    size_t ret = count_friendlist(tox->m);
    unlock(tox);
    return ret;
}

void tox_self_get_friend_list(const Tox *tox, uint32_t *friend_list)
{
    if (friend_list) {
        lock(tox);
        // TODO(irungentoo): size parameter?
        copy_friendlist(tox->m, friend_list, count_friendlist(tox->m));
        unlock(tox);
    }
}

size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    lock(tox);
    const int ret = m_get_name_size(tox->m, friend_number);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, Tox_Err_Friend_Query *error)
{
    if (!name) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    lock(tox);
    const int ret = getname(tox->m, friend_number, name);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *callback)
{
    tox->friend_name_callback = callback;
}

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    lock(tox);
    const int ret = m_get_statusmessage_size(tox->m, friend_number);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *status_message,
                                   Tox_Err_Friend_Query *error)
{
    if (!status_message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return false;
    }

    lock(tox);
    const int size = m_get_statusmessage_size(tox->m, friend_number);

    if (size == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        unlock(tox);
        return false;
    }

    const int ret = m_copy_statusmessage(tox->m, friend_number, status_message, size);
    LOGGER_ASSERT(tox->m->log, ret == size, "concurrency problem: friend status message changed");

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    unlock(tox);
    return ret == size;
}

void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *callback)
{
    tox->friend_status_message_callback = callback;
}

Tox_User_Status tox_friend_get_status(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    lock(tox);
    const int ret = m_get_userstatus(tox->m, friend_number);
    unlock(tox);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return (Tox_User_Status)(TOX_USER_STATUS_BUSY + 1);
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (Tox_User_Status)ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback)
{
    tox->friend_status_callback = callback;
}

Tox_Connection tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    lock(tox);
    const int ret = m_get_friend_connectionstatus(tox->m, friend_number);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return (Tox_Connection)ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback)
{
    tox->friend_connection_status_callback = callback;
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, Tox_Err_Friend_Query *error)
{
    lock(tox);
    const int ret = m_get_istyping(tox->m, friend_number);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return !!ret;
}

void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *callback)
{
    tox->friend_typing_callback = callback;
}

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, Tox_Err_Set_Typing *error)
{
    lock(tox);

    if (m_set_usertyping(tox->m, friend_number, typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        unlock(tox);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    unlock(tox);
    return 1;
}

static void set_message_error(const Logger *log, int ret, Tox_Err_Friend_Send_Message *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
            break;

        case -5:
            LOGGER_FATAL(log, "impossible: Messenger and Tox disagree on message types");
            break;

        default:
            /* can't happen */
            LOGGER_FATAL(log, "impossible: unknown send-message error: %d", ret);
            break;
    }
}

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message,
                                 size_t length, Tox_Err_Friend_Send_Message *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_NULL);
        return 0;
    }

    if (!length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY);
        return 0;
    }

    uint32_t message_id = 0;
    lock(tox);
    set_message_error(tox->m->log, m_send_message_generic(tox->m, friend_number, type, message, length, &message_id),
                      error);
    unlock(tox);
    return message_id;
}

void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *callback)
{
    tox->friend_read_receipt_callback = callback;
}

void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *callback)
{
    tox->friend_request_callback = callback;
}

void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *callback)
{
    tox->friend_message_callback = callback;
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || (length && !data)) {
        return 0;
    }

    crypto_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, Tox_File_Control control,
                      Tox_Err_File_Control *error)
{
    lock(tox);
    const int ret = file_control(tox->m, friend_number, file_number, control);
    unlock(tox);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_FOUND);
            return 0;

        case -4:
            /* can't happen */
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_ALREADY_PAUSED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_DENIED);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_PAUSED);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                   Tox_Err_File_Seek *error)
{
    lock(tox);
    const int ret = file_seek(tox->m, friend_number, file_number, position);
    unlock(tox);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_NOT_FOUND);
            return 0;

        case -4: // fall-through
        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_DENIED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_INVALID_POSITION);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback)
{
    tox->file_recv_control_callback = callback;
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          Tox_Err_File_Get *error)
{
    if (!file_id) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NULL);
        return 0;
    }

    lock(tox);
    const int ret = file_get_id(tox->m, friend_number, file_number, file_id);
    unlock(tox);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_OK);
        return 1;
    }

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_FRIEND_NOT_FOUND);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NOT_FOUND);
    }

    return 0;
}

uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, Tox_Err_File_Send *error)
{
    if (filename_length && !filename) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NULL);
        return UINT32_MAX;
    }

    uint8_t f_id[FILE_ID_LENGTH];

    if (!file_id) {
        /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
        new_symmetric_key(f_id);
        file_id = f_id;
    }

    lock(tox);
    const long int file_num = new_filesender(tox->m, friend_number, kind, file_size, file_id, filename, filename_length);
    unlock(tox);

    if (file_num >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_OK);
        return file_num;
    }

    switch (file_num) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NAME_TOO_LONG);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_TOO_MANY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, Tox_Err_File_Send_Chunk *error)
{
    lock(tox);
    const int ret = file_data(tox->m, friend_number, file_number, position, data, length);
    unlock(tox);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_SENDQ);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback)
{
    tox->file_chunk_request_callback = callback;
}

void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *callback)
{
    tox->file_recv_callback = callback;
}

void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback)
{
    tox->file_recv_chunk_callback = callback;
}

void tox_callback_conference_invite(Tox *tox, tox_conference_invite_cb *callback)
{
    tox->conference_invite_callback = callback;
}

void tox_callback_conference_connected(Tox *tox, tox_conference_connected_cb *callback)
{
    tox->conference_connected_callback = callback;
}

void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback)
{
    tox->conference_message_callback = callback;
}

void tox_callback_conference_title(Tox *tox, tox_conference_title_cb *callback)
{
    tox->conference_title_callback = callback;
}

void tox_callback_conference_peer_name(Tox *tox, tox_conference_peer_name_cb *callback)
{
    tox->conference_peer_name_callback = callback;
}

void tox_callback_conference_peer_list_changed(Tox *tox, tox_conference_peer_list_changed_cb *callback)
{
    tox->conference_peer_list_changed_callback = callback;
}

uint32_t tox_conference_new(Tox *tox, Tox_Err_Conference_New *error)
{
    lock(tox);
    const int ret = add_groupchat(tox->m->conferences_object, GROUPCHAT_TYPE_TEXT);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_INIT);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_NEW_OK);
    return ret;
}

bool tox_conference_delete(Tox *tox, uint32_t conference_number, Tox_Err_Conference_Delete *error)
{
    lock(tox);
    const int ret = del_groupchat(tox->m->conferences_object, conference_number, true);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_DELETE_OK);
    return true;
}

uint32_t tox_conference_peer_count(const Tox *tox, uint32_t conference_number, Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_number_peers(tox->m->conferences_object, conference_number, false);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

size_t tox_conference_peer_get_name_size(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
        Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peername_size(tox->m->conferences_object, conference_number, peer_number, false);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_peer_get_name(const Tox *tox, uint32_t conference_number, uint32_t peer_number, uint8_t *name,
                                  Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peername(tox->m->conferences_object, conference_number, peer_number, name, false);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_get_public_key(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        uint8_t *public_key, Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peer_pubkey(tox->m->conferences_object, conference_number, peer_number, public_key, false);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_peer_number_is_ours(const Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peernumber_is_ours(tox->m->conferences_object, conference_number, peer_number);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

uint32_t tox_conference_offline_peer_count(const Tox *tox, uint32_t conference_number,
        Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_number_peers(tox->m->conferences_object, conference_number, true);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

size_t tox_conference_offline_peer_get_name_size(const Tox *tox, uint32_t conference_number,
        uint32_t offline_peer_number,
        Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peername_size(tox->m->conferences_object, conference_number, offline_peer_number, true);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return ret;
}

bool tox_conference_offline_peer_get_name(const Tox *tox, uint32_t conference_number, uint32_t offline_peer_number,
        uint8_t *name,
        Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peername(tox->m->conferences_object, conference_number, offline_peer_number, name, true);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

bool tox_conference_offline_peer_get_public_key(const Tox *tox, uint32_t conference_number,
        uint32_t offline_peer_number,
        uint8_t *public_key, Tox_Err_Conference_Peer_Query *error)
{
    lock(tox);
    const int ret = group_peer_pubkey(tox->m->conferences_object, conference_number, offline_peer_number, public_key, true);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return true;
}

uint64_t tox_conference_offline_peer_get_last_active(const Tox *tox, uint32_t conference_number,
        uint32_t offline_peer_number,
        Tox_Err_Conference_Peer_Query *error)
{
    uint64_t last_active = UINT64_MAX;
    lock(tox);
    const int ret = group_frozen_last_active(tox->m->conferences_object, conference_number, offline_peer_number,
                    &last_active);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND);
            return UINT64_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND);
            return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_PEER_QUERY_OK);
    return last_active;
}

bool tox_conference_set_max_offline(Tox *tox, uint32_t conference_number,
                                    uint32_t max_offline_peers,
                                    Tox_Err_Conference_Set_Max_Offline *error)
{
    lock(tox);
    const int ret = group_set_max_frozen(tox->m->conferences_object, conference_number, max_offline_peers);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_CONFERENCE_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK);
    return true;
}

bool tox_conference_invite(Tox *tox, uint32_t friend_number, uint32_t conference_number,
                           Tox_Err_Conference_Invite *error)
{
    lock(tox);
    const int ret = invite_friend(tox->m->conferences_object, friend_number, conference_number);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_FAIL_SEND);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_NO_CONNECTION);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_INVITE_OK);
    return true;
}

uint32_t tox_conference_join(Tox *tox, uint32_t friend_number, const uint8_t *cookie, size_t length,
                             Tox_Err_Conference_Join *error)
{
    lock(tox);
    const int ret = join_groupchat(tox->m->conferences_object, friend_number, GROUPCHAT_TYPE_TEXT, cookie, length);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_DUPLICATE);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_INIT_FAIL);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_FAIL_SEND);
            return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_JOIN_OK);
    return ret;
}

bool tox_conference_send_message(Tox *tox, uint32_t conference_number, Tox_Message_Type type, const uint8_t *message,
                                 size_t length, Tox_Err_Conference_Send_Message *error)
{
    lock(tox);
    int ret = 0;

    if (type == TOX_MESSAGE_TYPE_NORMAL) {
        ret = group_message_send(tox->m->conferences_object, conference_number, message, length);
    } else {
        ret = group_action_send(tox->m->conferences_object, conference_number, message, length);
    }

    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION);
            return false;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_SEND_MESSAGE_OK);
    return true;
}

size_t tox_conference_get_title_size(const Tox *tox, uint32_t conference_number, Tox_Err_Conference_Title *error)
{
    lock(tox);
    const int ret = group_title_get_size(tox->m->conferences_object, conference_number);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return -1;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return ret;
}

bool tox_conference_get_title(const Tox *tox, uint32_t conference_number, uint8_t *title,
                              Tox_Err_Conference_Title *error)
{
    lock(tox);
    const int ret = group_title_get(tox->m->conferences_object, conference_number, title);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

bool tox_conference_set_title(Tox *tox, uint32_t conference_number, const uint8_t *title, size_t length,
                              Tox_Err_Conference_Title *error)
{
    lock(tox);
    const int ret = group_title_send(tox->m->conferences_object, conference_number, title, length);
    unlock(tox);

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND);
            return false;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);
            return false;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_FAIL_SEND);
            return false;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_TITLE_OK);
    return true;
}

size_t tox_conference_get_chatlist_size(const Tox *tox)
{
    lock(tox);
    size_t ret = count_chatlist(tox->m->conferences_object);
    unlock(tox);
    return ret;
}

void tox_conference_get_chatlist(const Tox *tox, uint32_t *chatlist)
{
    lock(tox);
    const size_t list_size = count_chatlist(tox->m->conferences_object);
    copy_chatlist(tox->m->conferences_object, chatlist, list_size);
    unlock(tox);
}

Tox_Conference_Type tox_conference_get_type(const Tox *tox, uint32_t conference_number,
        Tox_Err_Conference_Get_Type *error)
{
    lock(tox);
    const int ret = group_get_type(tox->m->conferences_object, conference_number);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND);
        return (Tox_Conference_Type)ret;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_GET_TYPE_OK);
    return (Tox_Conference_Type)ret;
}

/* id is TOX_CONFERENCE_ID_SIZE bytes */
bool tox_conference_get_id(const Tox *tox, uint32_t conference_number, uint8_t *id)
{
    lock(tox);
    bool ret = conference_get_id(tox->m->conferences_object, conference_number, id);
    unlock(tox);
    return ret;
}

// TODO(iphydf): Delete in 0.3.0.
/* uid is TOX_CONFERENCE_ID_SIZE bytes */
bool tox_conference_get_uid(const Tox *tox, uint32_t conference_number, uint8_t *uid)
{
    return tox_conference_get_id(tox, conference_number, uid);
}

uint32_t tox_conference_by_id(const Tox *tox, const uint8_t *id, Tox_Err_Conference_By_Id *error)
{
    if (!id) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_ID_NULL);
        return UINT32_MAX;
    }

    lock(tox);
    const int32_t ret = conference_by_id(tox->m->conferences_object, id);
    unlock(tox);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_ID_OK);
    return ret;
}

// TODO(iphydf): Delete in 0.3.0.
uint32_t tox_conference_by_uid(const Tox *tox, const uint8_t *uid, Tox_Err_Conference_By_Uid *error)
{
    Tox_Err_Conference_By_Id id_error;
    const uint32_t res = tox_conference_by_id(tox, uid, &id_error);

    switch (id_error) {
        case TOX_ERR_CONFERENCE_BY_ID_OK:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_OK);
            break;

        case TOX_ERR_CONFERENCE_BY_ID_NULL:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_NULL);
            break;

        case TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND:
            SET_ERROR_PARAMETER(error, TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND);
            break;
    }

    return res;
}

static void set_custom_packet_error(int ret, Tox_Err_Friend_Custom_Packet *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED);
            break;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ);
            break;
    }
}

bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  Tox_Err_Friend_Custom_Packet *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    if (data[0] < PACKET_ID_RANGE_LOSSY_START || data[0] > PACKET_ID_RANGE_LOSSY_END) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
        return 0;
    }

    lock(tox);
    const int ret = m_send_custom_lossy_packet(tox->m, friend_number, data, length);
    unlock(tox);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *callback)
{
    /* start at PACKET_ID_RANGE_LOSSY_CUSTOM_START so ToxAV Packets are excluded */
    for (uint8_t i = PACKET_ID_RANGE_LOSSY_CUSTOM_START; i <= PACKET_ID_RANGE_LOSSY_END; ++i) {
        tox->friend_lossy_packet_callback_per_pktid[i] = callback;
    }
}

void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid)
{
    if (pktid >= PACKET_ID_RANGE_LOSSY_START && pktid <= PACKET_ID_RANGE_LOSSY_END) {
        tox->friend_lossy_packet_callback_per_pktid[pktid] = callback;
    }
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     Tox_Err_Friend_Custom_Packet *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    lock(tox);
    const int ret = send_custom_lossless_packet(tox->m, friend_number, data, length);
    unlock(tox);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    }

    return 0;
}

void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback)
{
    for (uint8_t i = PACKET_ID_RANGE_LOSSLESS_CUSTOM_START; i <= PACKET_ID_RANGE_LOSSLESS_CUSTOM_END; ++i) {
        tox->friend_lossless_packet_callback_per_pktid[i] = callback;
    }
}

void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid)
{
    if ((pktid >= PACKET_ID_RANGE_LOSSLESS_CUSTOM_START && pktid <= PACKET_ID_RANGE_LOSSLESS_CUSTOM_END)
            || pktid == PACKET_ID_MSI) {
        tox->friend_lossless_packet_callback_per_pktid[pktid] = callback;
    }
}

void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id)
{
    if (dht_id) {
        lock(tox);
        memcpy(dht_id, dht_get_self_public_key(tox->m->dht), CRYPTO_PUBLIC_KEY_SIZE);
        unlock(tox);
    }
}

void tox_set_av_object(Tox *tox, void *object)
{
    lock(tox);
    tox->toxav_object = object;
    unlock(tox);
}

void *tox_get_av_object(const Tox *tox)
{
    lock(tox);
    void *object = tox->toxav_object;
    unlock(tox);
    return object;
}

uint16_t tox_self_get_udp_port(const Tox *tox, Tox_Err_Get_Port *error)
{
    lock(tox);
    const uint16_t port = net_htons(net_port(tox->m->net));
    unlock(tox);

    if (port) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    }

    return port;
}

uint16_t tox_self_get_tcp_port(const Tox *tox, Tox_Err_Get_Port *error)
{
    lock(tox);

    if (tox->m->tcp_server) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
        uint16_t ret = tox->m->options.tcp_server_port;
        unlock(tox);
        return ret;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    unlock(tox);
    return 0;
}

/* GROUPCHAT FUNCTIONS */

#ifndef VANILLA_NACL
void tox_callback_group_invite(Tox *tox, tox_group_invite_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_invite_callback = function;
}

void tox_callback_group_message(Tox *tox, tox_group_message_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_message_callback = function;
}

void tox_callback_group_private_message(Tox *tox, tox_group_private_message_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_private_message_callback = function;
}

void tox_callback_group_custom_packet(Tox *tox, tox_group_custom_packet_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_custom_packet_callback = function;
}

void tox_callback_group_moderation(Tox *tox, tox_group_moderation_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_moderation_callback = function;
}

void tox_callback_group_peer_name(Tox *tox, tox_group_peer_name_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_peer_name_callback = function;
}

void tox_callback_group_peer_status(Tox *tox, tox_group_peer_status_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_peer_status_callback = function;
}

void tox_callback_group_topic(Tox *tox, tox_group_topic_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_topic_callback = function;
}

void tox_callback_group_privacy_state(Tox *tox, tox_group_privacy_state_cb *function, void *user_data)
{
    assert(user_data == nullptr);
    tox->group_privacy_state_callback = function;
}

void tox_callback_group_peer_limit(Tox *tox, tox_group_peer_limit_cb *function, void *user_data)
{
    assert(user_data == nullptr);
    tox->group_peer_limit_callback = function;
}

void tox_callback_group_password(Tox *tox, tox_group_password_cb *function, void *user_data)
{
    assert(user_data == nullptr);
    tox->group_password_callback = function;
}

void tox_callback_group_peer_join(Tox *tox, tox_group_peer_join_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_peer_join_callback = function;
}

void tox_callback_group_peer_exit(Tox *tox, tox_group_peer_exit_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_peer_exit_callback = function;
}

void tox_callback_group_self_join(Tox *tox, tox_group_self_join_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_self_join_callback = function;
}

void tox_callback_group_join_fail(Tox *tox, tox_group_join_fail_cb *function, void *userdata)
{
    assert(userdata == nullptr);
    tox->group_join_fail_callback = function;
}

uint32_t tox_group_new(Tox *tox, Tox_Group_Privacy_State privacy_state, const uint8_t *group_name, size_t length,
                       Tox_Err_Group_New *error)
{
    Messenger *m = tox->m;
    int ret = gc_group_add(m->group_handler, privacy_state, group_name, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_TOO_LONG);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_EMPTY);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_PRIVACY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_INIT);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_STATE);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_ANNOUNCE);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

uint32_t tox_group_join(Tox *tox, const uint8_t *chat_id, const uint8_t *password, size_t length,
                        Tox_Err_Group_Join *error)
{
    Messenger *m = tox->m;
    int ret = gc_group_join(m->group_handler, chat_id, password, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_INIT);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_BAD_CHAT_ID);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_reconnect(Tox *tox, uint32_t groupnumber, Tox_Err_Group_Reconnect *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND);
        return 0;
    }

    gc_rejoin_group(m->group_handler, chat);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_OK);
    return 1;
}

bool tox_group_leave(Tox *tox, uint32_t groupnumber, const uint8_t *partmessage, size_t length,
                     Tox_Err_Group_Leave *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_group_exit(m->group_handler, chat, partmessage, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_FAIL_SEND);
            return 1;   /* the group was still successfully deleted */

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_DELETE_FAIL);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_self_set_name(Tox *tox, uint32_t groupnumber, const uint8_t *name, size_t length,
                             Tox_Err_Group_Self_Name_Set *error)
{
    Messenger *m = tox->m;
    int ret = gc_set_self_nick(m, groupnumber, name, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_INVALID);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TAKEN);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_self_get_name_size(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_nick_size(chat);
}

bool tox_group_self_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *name, Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_nick(chat, name);
    return 1;
}

bool tox_group_self_set_status(Tox *tox, uint32_t groupnumber, Tox_User_Status status,
                               Tox_Err_Group_Self_Status_Set *error)
{
    Messenger *m = tox->m;
    int ret = gc_set_self_status(m, groupnumber, status);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

Tox_User_Status tox_group_self_get_status(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (Tox_User_Status) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t status = gc_get_self_status(chat);
    return (Tox_User_Status)status;
}

Tox_Group_Role tox_group_self_get_role(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return (Tox_Group_Role) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    uint8_t role = gc_get_self_role(chat);
    return (Tox_Group_Role)role;
}

uint32_t tox_group_self_get_peer_id(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_peer_id(chat);
}

bool tox_group_self_get_public_key(const Tox *tox, uint32_t groupnumber, uint8_t *public_key,
                                   Tox_Err_Group_Self_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_public_key(chat, public_key);
    return 1;
}

size_t tox_group_peer_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                    Tox_Err_Group_Peer_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    int ret = gc_get_peer_nick_size(chat, peer_id);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
        return ret;
    }
}

bool tox_group_peer_get_name(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *name,
                             Tox_Err_Group_Peer_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_nick(chat, peer_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

Tox_User_Status tox_group_peer_get_status(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
        Tox_Err_Group_Peer_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return (Tox_User_Status) - 1;
    }

    uint8_t ret = gc_get_status(chat, peer_id);

    if (ret == (uint8_t) - 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return (Tox_User_Status) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return (Tox_User_Status)ret;
}

Tox_Group_Role tox_group_peer_get_role(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                       Tox_Err_Group_Peer_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return (Tox_Group_Role) - 1;
    }

    uint8_t ret = gc_get_role(chat, peer_id);

    if (ret == (uint8_t) - 1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return (Tox_Group_Role) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return (Tox_Group_Role)ret;
}

bool tox_group_peer_get_public_key(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *public_key,
                                   Tox_Err_Group_Peer_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_public_key(chat, peer_id, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

bool tox_group_set_topic(Tox *tox, uint32_t groupnumber, const uint8_t *topic, size_t length,
                         Tox_Err_Group_Topic_Set *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_set_topic(chat, topic, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_get_topic_size(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_topic_size(chat);
}

bool tox_group_get_topic(const Tox *tox, uint32_t groupnumber, uint8_t *topic, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_topic(chat, topic);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

size_t tox_group_get_name_size(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_group_name_size(chat);
}

bool tox_group_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *groupname, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_group_name(chat, groupname);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

bool tox_group_get_chat_id(const Tox *tox, uint32_t groupnumber, uint8_t *chat_id, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_chat_id(chat, chat_id);
    return 1;
}

uint32_t tox_group_get_number_groups(const Tox *tox)
{
    const Messenger *m = tox->m;
    return gc_count_groups(m->group_handler);
}

Tox_Group_Privacy_State tox_group_get_privacy_state(const Tox *tox, uint32_t groupnumber,
        Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return (Tox_Group_Privacy_State) - 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    uint8_t state = gc_get_privacy_state(chat);
    return (Tox_Group_Privacy_State)state;
}

uint32_t tox_group_get_peer_limit(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_max_peers(chat);
}

size_t tox_group_get_password_size(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_password_size(chat);
}

bool tox_group_get_password(const Tox *tox, uint32_t groupnumber, uint8_t *password, Tox_Err_Group_State_Queries *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_password(chat, password);
    return 1;
}

bool tox_group_send_message(Tox *tox, uint32_t groupnumber, Tox_Message_Type type, const uint8_t *message,
                            size_t length, Tox_Err_Group_Send_Message *error)
{
    const Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_message(chat, message, length, type);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_private_message(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *message,
                                    size_t length, Tox_Err_Group_Send_Private_Message *error)
{
    const Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_private_message(chat, peer_id, message, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_custom_packet(Tox *tox, uint32_t groupnumber, bool lossless, const uint8_t *data,
                                  size_t length, Tox_Err_Group_Send_Custom_Packet *error)
{
    const Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_custom_packet(chat, lossless, data, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_invite_friend(Tox *tox, uint32_t groupnumber, uint32_t friend_number, Tox_Err_Group_Invite_Friend *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND);
        return 0;
    }

    if (!friend_is_valid(m, friend_number)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND);
        return 0;
    }

    int ret = gc_invite_friend(m->group_handler, chat, friend_number,
                               send_group_invite_packet);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

uint32_t tox_group_invite_accept(Tox *tox, const uint8_t *invite_data, size_t length, const uint8_t *password,
                                 size_t password_length, Tox_Err_Group_Invite_Accept *error)
{
    Messenger *m = tox->m;
    int ret = gc_accept_invite(m->group_handler, invite_data, length, password, password_length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_founder_set_password(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                    Tox_Err_Group_Founder_Set_Password *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_founder_set_password(chat, password, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_privacy_state(Tox *tox, uint32_t groupnumber, Tox_Group_Privacy_State privacy_state,
        Tox_Err_Group_Founder_Set_Privacy_State *error)
{
    Messenger *m = tox->m;
    int ret = gc_founder_set_privacy_state(m, groupnumber, privacy_state);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_peer_limit(Tox *tox, uint32_t groupnumber, uint32_t maxpeers,
                                      Tox_Err_Group_Founder_Set_Peer_Limit *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_founder_set_max_peers(chat, groupnumber, maxpeers);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_toggle_ignore(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool ignore,
                             Tox_Err_Group_Toggle_Ignore *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_toggle_ignore(chat, peer_id, ignore);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_PEER_NOT_FOUND);
        return 0;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_OK);
        return 1;
    }
}

bool tox_group_mod_set_role(Tox *tox, uint32_t groupnumber, uint32_t peer_id, Tox_Group_Role role,
                            Tox_Err_Group_Mod_Set_Role *error)
{
    Messenger *m = tox->m;
    int ret = gc_set_peer_role(m, groupnumber, peer_id, role);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_peer(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool set_ban,
                               Tox_Err_Group_Mod_Remove_Peer *error)
{
    Messenger *m = tox->m;
    int ret = gc_remove_peer(m, groupnumber, peer_id, set_ban);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_ACTION);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_ban(Tox *tox, uint32_t groupnumber, uint32_t ban_id, Tox_Err_Group_Mod_Remove_Ban *error)
{
    Messenger *m = tox->m;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_remove_ban(chat, ban_id);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_ACTION);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_ban_get_list_size(const Tox *tox, uint32_t groupnumber, Tox_Err_Group_Ban_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return sanctions_list_num_banned(chat);
}

bool tox_group_ban_get_list(const Tox *tox, uint32_t groupnumber, uint32_t *list, Tox_Err_Group_Ban_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    sanctions_list_get_ban_list(chat, list);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

size_t tox_group_ban_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                   Tox_Err_Group_Ban_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint16_t ret = sanctions_list_get_ban_nick_length(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}

bool tox_group_ban_get_name(const Tox *tox, uint32_t groupnumber, uint32_t ban_id, uint8_t *name,
                            Tox_Err_Group_Ban_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = sanctions_list_get_ban_nick(chat, ban_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

uint64_t tox_group_ban_get_time_set(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                    Tox_Err_Group_Ban_Query *error)
{
    const Messenger *m = tox->m;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint64_t ret = sanctions_list_get_ban_time_set(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}
#endif /* VANILLA_NACL */
