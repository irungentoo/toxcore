/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_MSI_H
#define C_TOXCORE_TOXAV_MSI_H

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#include "../toxcore/logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Error codes.
 */
typedef enum MSIError {
    MSI_E_NONE,
    MSI_E_INVALID_MESSAGE,
    MSI_E_INVALID_PARAM,
    MSI_E_INVALID_STATE,
    MSI_E_STRAY_MESSAGE,
    MSI_E_SYSTEM,
    MSI_E_HANDLE,
    MSI_E_UNDISCLOSED, /* NOTE: must be last enum otherwise parsing will not work */
} MSIError;

/**
 * Supported capabilities
 */
typedef enum MSICapabilities {
    MSI_CAP_S_AUDIO = 4,  /* sending audio */
    MSI_CAP_S_VIDEO = 8,  /* sending video */
    MSI_CAP_R_AUDIO = 16, /* receiving audio */
    MSI_CAP_R_VIDEO = 32, /* receiving video */
} MSICapabilities;

/**
 * Call state identifiers.
 */
typedef enum MSICallState {
    MSI_CALL_INACTIVE = 0, /* Default */
    MSI_CALL_ACTIVE = 1,
    MSI_CALL_REQUESTING = 2, /* when sending call invite */
    MSI_CALL_REQUESTED = 3, /* when getting call invite */
} MSICallState;

/**
 * Callbacks ids that handle the states
 */
typedef enum MSICallbackID {
    MSI_ON_INVITE = 0, /* Incoming call */
    MSI_ON_START = 1, /* Call (RTP transmission) started */
    MSI_ON_END = 2, /* Call that was active ended */
    MSI_ON_ERROR = 3, /* On protocol error */
    MSI_ON_PEERTIMEOUT = 4, /* Peer timed out; stop the call */
    MSI_ON_CAPABILITIES = 5, /* Peer requested capabilities change */
} MSICallbackID;

/**
 * The call struct. Please do not modify outside msi.c
 */
typedef struct MSICall {
    struct MSISession *_Nonnull session; /* Session pointer */

    MSICallState state;
    uint8_t peer_capabilities; /* Peer capabilities */
    uint8_t self_capabilities; /* Self capabilities */
    uint16_t peer_vfpsz; /* Video frame piece size */
    uint32_t friend_number; /* Index of this call in MSISession */
    MSIError error; /* Last error */

    void *_Nullable user_data; /* Pointer to av call handler */

    struct MSICall *_Nullable next;
    struct MSICall *_Nullable prev;
} MSICall;

/**
 * Expected return on success is 0, if any other number is
 * returned the call is considered errored and will be handled
 * as such which means it will be terminated without any notice.
 */
typedef int msi_action_cb(void *_Nullable object, MSICall *_Nonnull call);

/**
 * Send packet callback.
 *
 * @return 0 on success, -1 on failure.
 */
typedef int msi_send_packet_cb(void *_Nullable user_data, uint32_t friend_number, const uint8_t *_Nonnull data, size_t length);

/**
 * MSI callbacks.
 */
typedef struct MSICallbacks {
    msi_action_cb *_Nonnull invite;
    msi_action_cb *_Nonnull start;
    msi_action_cb *_Nonnull end;
    msi_action_cb *_Nonnull error;
    msi_action_cb *_Nonnull peertimeout;
    msi_action_cb *_Nonnull capabilities;
} MSICallbacks;

/**
 * Control session struct. Please do not modify outside msi.c
 */
typedef struct MSISession {
    /* Call handlers */
    MSICall *_Nullable *_Nullable calls;
    uint32_t calls_tail;
    uint32_t calls_head;

    void *_Nullable user_data;

    msi_send_packet_cb *_Nonnull send_packet;
    void *_Nullable send_packet_user_data;

    pthread_mutex_t mutex[1];

    msi_action_cb *_Nonnull invite_callback;
    msi_action_cb *_Nonnull start_callback;
    msi_action_cb *_Nonnull end_callback;
    msi_action_cb *_Nonnull error_callback;
    msi_action_cb *_Nonnull peertimeout_callback;
    msi_action_cb *_Nonnull capabilities_callback;
} MSISession;

/**
 * Start the control session.
 */
MSISession *_Nullable msi_new(const Logger *_Nonnull log,
                              msi_send_packet_cb *_Nonnull send_packet, void *_Nullable send_packet_user_data,
                              const MSICallbacks *_Nonnull callbacks,
                              void *_Nullable user_data);
/**
 * Terminate control session. NOTE: all calls will be freed
 */
int msi_kill(const Logger *_Nonnull log, MSISession *_Nullable session);
/**
 * Send invite request to friend_number.
 */
int msi_invite(const Logger *_Nonnull log, MSISession *_Nonnull session, MSICall *_Nonnull *_Nonnull call,
               uint32_t friend_number, uint8_t capabilities);
/**
 * Hangup call. NOTE: `call` will be freed
 */
int msi_hangup(const Logger *_Nonnull log, MSICall *_Nullable call);
/**
 * Answer call request.
 */
int msi_answer(const Logger *_Nonnull log, MSICall *_Nullable call, uint8_t capabilities);
/**
 * Change capabilities of the call.
 */
int msi_change_capabilities(const Logger *_Nonnull log, MSICall *_Nullable call, uint8_t capabilities);

/**
 * Handle incoming MSI packet.
 */
void msi_handle_packet(MSISession *_Nullable session, const Logger *_Nonnull log, uint32_t friend_number,
                       const uint8_t *_Nonnull data, size_t length);

/**
 * Mark a call as timed out.
 */
void msi_call_timeout(MSISession *_Nullable session, const Logger *_Nonnull log, uint32_t friend_number);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_MSI_H */
