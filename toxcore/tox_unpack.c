/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <stdint.h>

#include "bin_unpack.h"
#include "tox.h"

non_null()
static bool tox_conference_type_from_int(uint32_t value, Tox_Conference_Type *out)
{
    switch (value) {
        case TOX_CONFERENCE_TYPE_TEXT: {
            *out = TOX_CONFERENCE_TYPE_TEXT;
            return true;
        }

        case TOX_CONFERENCE_TYPE_AV: {
            *out = TOX_CONFERENCE_TYPE_AV;
            return true;
        }

        default: {
            *out = TOX_CONFERENCE_TYPE_TEXT;
            return false;
        }
    }
}
bool tox_conference_type_unpack(Bin_Unpack *bu, Tox_Conference_Type *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_conference_type_from_int(u32, val);
}

non_null()
static bool tox_connection_from_int(uint32_t value, Tox_Connection *out)
{
    switch (value) {
        case TOX_CONNECTION_NONE: {
            *out = TOX_CONNECTION_NONE;
            return true;
        }

        case TOX_CONNECTION_TCP: {
            *out = TOX_CONNECTION_TCP;
            return true;
        }

        case TOX_CONNECTION_UDP: {
            *out = TOX_CONNECTION_UDP;
            return true;
        }

        default: {
            *out = TOX_CONNECTION_NONE;
            return false;
        }
    }
}

bool tox_connection_unpack(Bin_Unpack *bu, Tox_Connection *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_connection_from_int(u32, val);
}

non_null()
static bool tox_file_control_from_int(uint32_t value, Tox_File_Control *out)
{
    switch (value) {
        case TOX_FILE_CONTROL_RESUME: {
            *out = TOX_FILE_CONTROL_RESUME;
            return true;
        }

        case TOX_FILE_CONTROL_PAUSE: {
            *out = TOX_FILE_CONTROL_PAUSE;
            return true;
        }

        case TOX_FILE_CONTROL_CANCEL: {
            *out = TOX_FILE_CONTROL_CANCEL;
            return true;
        }

        default: {
            *out = TOX_FILE_CONTROL_RESUME;
            return false;
        }
    }
}

bool tox_file_control_unpack(Bin_Unpack *bu, Tox_File_Control *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_file_control_from_int(u32, val);
}

non_null()
static bool tox_message_type_from_int(uint32_t value, Tox_Message_Type *out)
{
    switch (value) {
        case TOX_MESSAGE_TYPE_NORMAL: {
            *out = TOX_MESSAGE_TYPE_NORMAL;
            return true;
        }

        case TOX_MESSAGE_TYPE_ACTION: {
            *out = TOX_MESSAGE_TYPE_ACTION;
            return true;
        }

        default: {
            *out = TOX_MESSAGE_TYPE_NORMAL;
            return false;
        }
    }
}

bool tox_message_type_unpack(Bin_Unpack *bu, Tox_Message_Type *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_message_type_from_int(u32, val);
}

non_null()
static bool tox_user_status_from_int(uint32_t value, Tox_User_Status *out)
{
    switch (value) {
        case TOX_USER_STATUS_NONE: {
            *out = TOX_USER_STATUS_NONE;
            return true;
        }

        case TOX_USER_STATUS_AWAY: {
            *out = TOX_USER_STATUS_AWAY;
            return true;
        }

        case TOX_USER_STATUS_BUSY: {
            *out = TOX_USER_STATUS_BUSY;
            return true;
        }

        default: {
            *out = TOX_USER_STATUS_NONE;
            return false;
        }
    }
}

bool tox_user_status_unpack(Bin_Unpack *bu, Tox_User_Status *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_user_status_from_int(u32, val);
}

non_null()
static bool tox_group_privacy_state_from_int(uint32_t value, Tox_Group_Privacy_State *out)
{
  switch (value) {
    case TOX_GROUP_PRIVACY_STATE_PUBLIC: {
      *out = TOX_GROUP_PRIVACY_STATE_PUBLIC;
      return true;
    }
    case TOX_GROUP_PRIVACY_STATE_PRIVATE: {
      *out = TOX_GROUP_PRIVACY_STATE_PRIVATE;
      return true;
    }
    default: {
      *out = TOX_GROUP_PRIVACY_STATE_PUBLIC;
      return false;
    }
  }
}
bool tox_group_privacy_state_unpack(Bin_Unpack *bu, Tox_Group_Privacy_State *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_privacy_state_from_int(u32, val);
}
non_null()
static bool tox_group_voice_state_from_int(uint32_t value, Tox_Group_Voice_State *out)
{
  switch (value) {
    case TOX_GROUP_VOICE_STATE_ALL: {
      *out = TOX_GROUP_VOICE_STATE_ALL;
      return true;
    }
    case TOX_GROUP_VOICE_STATE_MODERATOR: {
      *out = TOX_GROUP_VOICE_STATE_MODERATOR;
      return true;
    }
    case TOX_GROUP_VOICE_STATE_FOUNDER: {
      *out = TOX_GROUP_VOICE_STATE_FOUNDER;
      return true;
    }
    default: {
      *out = TOX_GROUP_VOICE_STATE_ALL;
      return false;
    }
  }
}
bool tox_group_voice_state_unpack(Bin_Unpack *bu, Tox_Group_Voice_State *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_voice_state_from_int(u32, val);
}

non_null()
static bool tox_group_topic_lock_from_int(uint32_t value, Tox_Group_Topic_Lock *out)
{
  switch (value) {
    case TOX_GROUP_TOPIC_LOCK_ENABLED: {
      *out = TOX_GROUP_TOPIC_LOCK_ENABLED;
      return true;
    }
    case TOX_GROUP_TOPIC_LOCK_DISABLED: {
      *out = TOX_GROUP_TOPIC_LOCK_DISABLED;
      return true;
    }
    default: {
      *out = TOX_GROUP_TOPIC_LOCK_ENABLED;
      return false;
    }
  }
}
bool tox_group_topic_lock_unpack(Bin_Unpack *bu, Tox_Group_Topic_Lock *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_topic_lock_from_int(u32, val);
}

non_null()
static bool tox_group_join_fail_from_int(uint32_t value, Tox_Group_Join_Fail *out)
{
  switch (value) {
    case TOX_GROUP_JOIN_FAIL_PEER_LIMIT: {
      *out = TOX_GROUP_JOIN_FAIL_PEER_LIMIT;
      return true;
    }
    case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD: {
      *out = TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD;
      return true;
    }
    case TOX_GROUP_JOIN_FAIL_UNKNOWN: {
      *out = TOX_GROUP_JOIN_FAIL_UNKNOWN;
      return true;
    }
    default: {
      *out = TOX_GROUP_JOIN_FAIL_PEER_LIMIT;
      return false;
    }
  }
}
bool tox_group_join_fail_unpack(Bin_Unpack *bu, Tox_Group_Join_Fail *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_join_fail_from_int(u32, val);
}

non_null()
static bool tox_group_mod_event_from_int(uint32_t value, Tox_Group_Mod_Event *out)
{
  switch (value) {
    case TOX_GROUP_MOD_EVENT_KICK: {
      *out = TOX_GROUP_MOD_EVENT_KICK;
      return true;
    }
    case TOX_GROUP_MOD_EVENT_OBSERVER: {
      *out = TOX_GROUP_MOD_EVENT_OBSERVER;
      return true;
    }
    case TOX_GROUP_MOD_EVENT_USER: {
      *out = TOX_GROUP_MOD_EVENT_USER;
      return true;
    }
    case TOX_GROUP_MOD_EVENT_MODERATOR: {
      *out = TOX_GROUP_MOD_EVENT_MODERATOR;
      return true;
    }
    default: {
      *out = TOX_GROUP_MOD_EVENT_KICK;
      return false;
    }
  }
}
bool tox_group_mod_event_unpack(Bin_Unpack *bu, Tox_Group_Mod_Event *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_mod_event_from_int(u32, val);
}

non_null()
static bool tox_group_exit_type_from_int(uint32_t value, Tox_Group_Exit_Type *out)
{
  switch (value) {
    case TOX_GROUP_EXIT_TYPE_QUIT: {
      *out = TOX_GROUP_EXIT_TYPE_QUIT;
      return true;
    }
    case TOX_GROUP_EXIT_TYPE_TIMEOUT: {
      *out = TOX_GROUP_EXIT_TYPE_TIMEOUT;
      return true;
    }
    case TOX_GROUP_EXIT_TYPE_DISCONNECTED: {
      *out = TOX_GROUP_EXIT_TYPE_DISCONNECTED;
      return true;
    }
    case TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED: {
      *out = TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED;
      return true;
    }
    case TOX_GROUP_EXIT_TYPE_KICK: {
      *out = TOX_GROUP_EXIT_TYPE_KICK;
      return true;
    }
    case TOX_GROUP_EXIT_TYPE_SYNC_ERROR: {
      *out = TOX_GROUP_EXIT_TYPE_SYNC_ERROR;
      return true;
    }
    default: {
      *out = TOX_GROUP_EXIT_TYPE_QUIT;
      return false;
    }
  }
}
bool tox_group_exit_type_unpack(Bin_Unpack *bu, Tox_Group_Exit_Type *val)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_group_exit_type_from_int(u32, val);
}
