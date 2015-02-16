/**  msi.c
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include "msi.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define MSI_MAXMSG_SIZE 256

/* Define default timeout for a request.
 * There is no behavior specified by the msi on what will
 * client do on timeout, but to call timeout callback.
 */
#define m_deftout 10000 /* in milliseconds */

/**
 * Protocol:
 *
 * |id [1 byte]| |size [1 byte]| |data [$size bytes]| |...{repeat}| |0 {end byte}|
 */

typedef enum {
    IDRequest = 1,
    IDResponse,
    IDError,
    IDCapabilities,

} MSIHeaderID;

/**
 * Headers
 */
typedef enum {
    type_request,
    type_response,
} MSIMessageType;

typedef enum {
    requ_invite,
    requ_start,
    requ_reject,
    requ_end,
} MSIRequest;

typedef enum {
    resp_ringing,
    resp_starting,
    resp_error,
} MSIResponse;

#define GENERIC_HEADER(header, val_type) \
typedef struct { \
val_type value; \
_Bool exists; \
} MSIHeader##header;


GENERIC_HEADER ( Request, MSIRequest )
GENERIC_HEADER ( Response, MSIResponse )
GENERIC_HEADER ( Error, MSIError )
GENERIC_HEADER ( Capabilities, uint8_t )


typedef struct {
    MSIHeaderRequest      request;
    MSIHeaderResponse     response;
    MSIHeaderError        error;
    MSIHeaderCapabilities capabilities;
} MSIMessage;


static void invoke_callback(MSICall* c, MSICallbackID i)
{
    if ( c->session->callbacks[i] ) {
        LOGGER_DEBUG("Invoking callback function: %d", i);
        c->session->callbacks[i] ( c->session->agent_handler, c );
    }
}

/**
 * Create the message.
 */
static MSIMessage *msi_new_message ( MSIMessageType type, const uint8_t type_value )
{
    MSIMessage *retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( retu == NULL ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if ( type == type_request ) {
        retu->request.exists = 1;
        retu->request.value = type_value;

    } else {
        retu->response.exists = 1;
        retu->response.value = type_value;
    }

    return retu;
}


/**
 * Parse raw data received from socket into MSIMessage struct.
 */
static int parse_raw_data ( MSIMessage *msg, const uint8_t *data, uint16_t length )
{

#define CHECK_SIZE(bytes, constraint, size) \
    if ((constraint -= 3) < 1) { LOGGER_ERROR("Read over length!"); return -1; } \
    if ( bytes[1] != size ) { LOGGER_ERROR("Invalid data size!"); return -1; }
    
#define CHECK_ENUM_HIGH(bytes, enum_high) \
    if ( bytes[2] > enum_high ) { LOGGER_ERROR("Failed enum high limit!"); return -1; }
    
#define SET_VALUES(bytes, header) do { \
        header.value = bytes[2]; \
        header.exists = 1; \
        bytes += 3; \
    } while(0)


    if ( msg == NULL ) {
        LOGGER_ERROR("Could not parse message: no storage!");
        return -1;
    }

    if ( length == 0 || data[length - 1] ) { /* End byte must have value 0 */
        LOGGER_ERROR("Invalid end byte");
        return -1;
    }

    const uint8_t *it = data;
    int size_constraint = length;

    while ( *it ) {/* until end byte is hit */
        switch (*it) {
            case IDRequest:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, requ_end);
                SET_VALUES(it, msg->request);
                break;
                
            case IDResponse:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, resp_error);
                SET_VALUES(it, msg->response);
                it += 3;
                break;
                
            case IDError:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, msi_ErrUndisclosed);
                SET_VALUES(it, msg->error);
                break;
                
            case IDCapabilities:
                CHECK_SIZE(it, size_constraint, 1);
                SET_VALUES(it, msg->capabilities);
                break;
                
            default:
                LOGGER_ERROR("Invalid id byte");
                return -1;
                break;
        }
    }

    return 0;

#undef CHECK_SIZE
#undef CHECK_ENUM_HIGH
#undef SET_VALUES
}

/**
 * Parse data from handle_packet.
 */
static MSIMessage *parse_in ( const uint8_t *data, uint16_t length )
{
    if ( data == NULL ) {
        LOGGER_WARNING("Tried to parse empty message!");
        return NULL;
    }

    MSIMessage *retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( retu == NULL ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if ( parse_raw_data ( retu, data, length ) == -1 ) {

        free ( retu );
        return NULL;
    }

    return retu;
}


/**
 * Speaks for itself.
 */
static uint8_t *prepare_header ( MSIHeaderID id, uint8_t *dest, const void *value, 
                                 uint8_t value_len, uint16_t *length )
{
    if ( dest == NULL ) {
        LOGGER_ERROR("No destination space!");
        return NULL;
    }

    if (value == NULL || value_len == 0) {
        LOGGER_ERROR("Empty header value");
        return NULL;
    }

    *dest = id;
    dest ++;
    *dest = value_len;
    dest ++;

    memcpy(dest, value, value_len);

    *length += (2 + value_len);

    return dest + value_len; /* Set to next position ready to be written */
}


/**
 * Parse MSIMessage to send. Returns size in bytes of the parsed message
 */
static uint16_t parse_out ( MSIMessage *msg, uint8_t *dest )
{
    if (msg == NULL) {
        LOGGER_ERROR("No message!");
        return 0;
    }

    if (dest == NULL ) {
        LOGGER_ERROR("No destination!");
        return 0;
    }

    uint8_t *it = dest;
    uint16_t size = 0;

    if (msg->request.exists) {
        uint8_t cast = msg->request.value;
        it = prepare_header(IDRequest, it, &cast, 1, &size);
    }

    if (msg->response.exists) {
        uint8_t cast = msg->response.value;
        it = prepare_header(IDResponse, it, &cast, 1, &size);
    }

    if (msg->error.exists) {
        it = prepare_header(IDError, it, &msg->error.value, sizeof(msg->error.value), &size);
    }

    if (msg->capabilities.exists) {
        it = prepare_header(IDCapabilities, it, &msg->capabilities.value, 
                            sizeof(msg->capabilities.value), &size);
    }

    *it = 0;
    size ++;

    return size;
}

static int send_message ( MSICall *call, MSIMessage *msg, uint32_t to )
{
    uint8_t parsed [MSI_MAXMSG_SIZE];
    uint16_t length = parse_out ( msg, parsed );

    if ( !length ) {
        LOGGER_WARNING("Parsing message failed; nothing sent!");
        return -1;
    }
    
    if ( m_msi_packet(call->session->messenger_handle, to, parsed, length) ) {
        LOGGER_DEBUG("Sent message");
        return 0;
    }

    return -1;
}

static int send_reponse ( MSICall *call, MSIResponse response, uint32_t to )
{
    MSIMessage *msg = msi_new_message ( type_response, response );
    int ret = send_message ( call, msg, to );
    free ( msg );
    return ret;
}

static int send_error ( MSICall *call, MSIError error, uint32_t to )
{
    if (!call) {
        LOGGER_WARNING("Cannot handle error on 'null' call");
        return -1;
    }

    LOGGER_DEBUG("Sending error: %d on call: %d", error, call->call_idx);

    MSIMessage *msg_error = msi_new_message ( type_response, resp_error );
    
    if (!msg_error)
        return -1;
    
    msg_error->error.exists = 1;
    msg_error->error.value = error;
    
    send_message ( call, msg_error, to );
    free ( msg_error );

    return 0;
}


static MSICall *get_call ( MSISession *session, uint32_t friend_id )
{
    if (session->calls == NULL || session->calls_tail < friend_id)
        return NULL;
    
    return session->calls[friend_id];
}

static MSICall *new_call ( MSISession *session, uint32_t friend_id )
{
    MSICall *rc = calloc(sizeof(MSICall), 1);
    
    if (rc == NULL)
        return NULL;
    
    rc->friend_id = friend_id;
    
    if (session->calls == NULL) { /* Creating */
        session->calls = calloc (sizeof(MSICall*), friend_id + 1);
        
        if (session->calls == NULL) {
            free(rc);
            return NULL;
        }
        
        session->calls_tail = session->calls_head = friend_id;
        
    } else if (session->calls_tail < friend_id) { /* Appending */
        void* tmp = realloc(session->calls, sizeof(MSICall*) * friend_id + 1);
        
        if (tmp == NULL) {
            free(rc);
            return NULL;
        }
        
        session->calls = tmp;
        
        /* Set fields in between to null */
        int32_t i = session->calls_tail;
        for (; i < friend_id; i ++)
            session->calls[i] = NULL;
        
        rc->prev = session->calls[session->calls_tail];
        session->calls[session->calls_tail]->next = rc;
        
        session->calls_tail = friend_id;
        
    } else if (session->calls_head > friend_id) { /* Inserting at front */
        rc->next = session->calls[session->calls_head];
        session->calls[session->calls_head]->prev = rc;
        session->calls_head = friend_id;
    }
    
    session->calls[friend_id] = rc;
    return rc;
}

static void kill_call ( MSICall *call )
{
    if ( call == NULL )
        return;
    
    
    MSISession* session = call->session;
    
    MSICall* prev = call->prev;
    MSICall* next = call->next;
    
    if (prev)
        prev->next = next;
    else if (next)
        session->calls_head = next->friend_id;
    else goto CLEAR;
    
    if (next)
        next->prev = prev;
    else if (prev)
        session->calls_tail = prev->friend_id;
    else goto CLEAR;
    
    session->calls[call->friend_id] = NULL;
    free(call);
    return;
    
CLEAR:
    session->calls_head = session->calls_tail = 0;
    free(session->calls);
    session->calls = NULL;
    free(call);
}



static void handle_remote_connection_change(Messenger *messenger, int friend_id, uint8_t status, void *session_p)
{
    (void)messenger;
    MSISession *session = session_p;

    switch ( status ) {
        case 0: { /* Went offline */
            MSICall* call = get_call(session, friend_id);
            
            if (call == NULL)
                return;
            
            invoke_callback(call, msi_OnPeerTimeout);
            kill_call(call);
        }
        break;

        default:
            break;
    }
}



/********** Request handlers **********/
static int handle_recv_invite ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'invite' on no call");
        return -1;
    }
    
    MSISession* session = call->session;
    
    LOGGER_DEBUG("Session: %p Handling 'invite' friend: %d", call->session, call->friend_id);

    
    if ( call->state == msi_CallRequesting ) {
        /* The rare glare case.
         * Send starting and wait for starting by the other side.
         * The peer will do the same.
         * When you receive starting from peer send started.
         * Don't notice the app until the start is received.
         */
        
        LOGGER_DEBUG("Glare detected!");
        
        MSIMessage *msg_starting = msi_new_message ( type_response, resp_starting );
        
        call->capabilities &= msg->capabilities;
        
        msg_starting->capabilities.value = call->capabilities;
        msg_starting->capabilities.exists = 1;
        
        send_message ( call, msg_starting, call->friend_id );
        free ( msg_starting );
        
        return 0;
    }
    
    call->capabilities = msg->capabilities;
    call->state = msi_CallRequested;
    
    send_reponse(call, resp_ringing, call->friend_id);
    invoke_callback(call, msi_OnInvite);

    return 0;
}

static int handle_recv_start ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return -1;
    }
    
    if ( call->state != msi_CallRequested || call->state != msi_CallRequesting ) {
        LOGGER_WARNING("Session: %p Invalid call state on 'start'");
        /* TODO send error */
        return -1;
    }
    
    (void)msg;

    LOGGER_DEBUG("Session: %p Handling 'start', friend id: %d", call->session, call->friend_id );

    call->state = msi_CallActive;
    invoke_callback(call, msi_OnStart);
    
    return 0;
}

static int handle_recv_reject ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return -1;
    }
    
    (void)msg;
    
    if ( call->state != msi_CallRequesting ) {
        LOGGER_WARNING("Session: %p Invalid call state on 'reject'");
        /* TODO send error */
        return -1;
    }
    
    LOGGER_DEBUG("Session: %p Handling 'reject', friend id: %u", call->session, call->friend_id);

    invoke_callback(call, msi_OnReject);
    kill_call(call);

    return 0;
}

static int handle_recv_end ( MSICall *call, MSIMessage *msg )
{
    (void)msg;
    
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'end', friend id: %d", call->session, call->friend_id);

    invoke_callback(call, msi_OnEnd);
    kill_call ( call );

    return 0;
}

/********** Response handlers **********/
static int handle_recv_ringing ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return -1;
    }

    (void)msg;
    
    if ( call->state != msi_CallRequesting ) {
        LOGGER_WARNING("Session: %p Invalid call state on 'ringing'");
        /* TODO send error */
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'ringing' friend id: %d", call->session, call->friend_id );

    invoke_callback(call, msi_OnRinging);
    return 0;
}
static int handle_recv_starting ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'starting' on non-existing call");
        return 0;
    }
    
    if ( call->state != msi_CallRequested || call->state != msi_CallRequesting ) {
        LOGGER_WARNING("Session: %p Invalid call state on 'starting'");
        /* TODO send error */
        return -1;
    }
    
    MSIMessage *msg_start = msi_new_message ( type_request, requ_start );
    send_message ( call, msg_start, call->friend_id );
    free ( msg_start );
    
    if (call->state == msi_CallRequesting) {
        call->state = msi_CallActive;
        invoke_callback(call, msi_OnStart);
    } 
    
    /* Otherwise it's a glare case so don't start until 'start' is recved */
    
    return 0;
}
static int handle_recv_error ( MSICall *call, MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Handling 'error' on non-existing call!");
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'error' friend id: %d", call->session, call->friend_id );

    invoke_callback(call, msi_OnError);

    /* TODO Handle error accordingly */

    return -1;
}

/**
 * BASIC call flow:
 *
 *    ALICE                    BOB
 *      | invite -->            |
 *      |                       |
 *      |           <-- ringing |
 *      |                       |
 *      |          <-- starting |
 *      |                       |
 *      | start -->             |
 *      |                       |
 *      |  <-- MEDIA TRANS -->  |
 *      |                       |
 *      | end -->               |
 *      |                       |
 *      |            <-- ending |
 *
 * Alice calls Bob by sending invite packet.
 * Bob recvs the packet and sends an ringing packet;
 * which notifies Alice that her invite is acknowledged.
 * Ringing screen shown on both sides.
 * Bob accepts the invite for a call by sending starting packet.
 * Alice recvs the starting packet and sends the started packet to
 * inform Bob that she recved the starting packet.
 * Now the media transmission is established ( i.e. RTP transmission ).
 * Alice hangs up and sends end packet.
 * Bob recves the end packet and sends ending packet
 * as the acknowledgement that the call is ending.
 *
 *
 */
static void msi_handle_packet ( Messenger *messenger, int friend_id, const uint8_t *data, uint16_t length, void *object )
{
    LOGGER_DEBUG("Got msi message");
    
    /* Unused */
    (void)messenger;

    MSISession *session = object;
    MSIMessage *msg;

    msg = parse_in ( data, length );

    if ( !msg ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }
    
    pthread_mutex_lock(session->mutex);

    MSICall *call = get_call(session, friend_id);
    
    if (call == NULL) {
        if (msg->request != requ_invite) {
            /* TODO send error */
            return;
        }
        
        call = new_call(session, friend_id);
        if (call == NULL) {
            /* TODO send error */
            return;
        }
    }
    
    
    /* Now handle message */
    int rc = 0;
    if ( msg->request.exists ) { /* Handle request */
        switch (msg->request.value) {
            case requ_invite:
                rc = handle_recv_invite ( call, msg );
                break;

            case requ_start:
                rc = handle_recv_start ( call, msg );
                break;

            case requ_reject:
                rc = handle_recv_reject ( call, msg );
                break;

            case requ_end:
                rc = handle_recv_end ( call, msg );
                break;
        }
    } else if ( msg->response.exists ) { /* Handle response */
        switch (msg->response.value) {
            case resp_ringing:
                rc = handle_recv_ringing ( call, msg );
                break;

            case resp_starting:
                rc = handle_recv_starting ( call, msg );
                break;

            case resp_error:
                rc = handle_recv_error ( call, msg );
                break;
        }
    } else {
        LOGGER_WARNING("Invalid message: no resp nor requ headers");
        /* TODO send error */
        rc = -1;
    }
    
    if (rc == -1)
        kill_call(call);
    
    free ( msg );
    pthread_mutex_unlock(session->mutex);
}



/********** User functions **********/
void msi_register_callback ( MSISession *session, MSICallbackType callback, MSICallbackID id)
{
    session->callbacks[id] = callback;
}

MSISession *msi_new ( Messenger *messenger )
{
    if (messenger == NULL) {
        LOGGER_ERROR("Could not init session on empty messenger!");
        return NULL;
    }

    MSISession *retu = calloc ( sizeof ( MSISession ), 1 );

    if (retu == NULL) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(retu->mutex) != 0) {
        LOGGER_ERROR("Failed to init mutex! Program might misbehave");
        free(retu);
        return NULL;
    }

    retu->messenger_handle = messenger;

    m_callback_msi_packet(messenger, msi_handle_packet, retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, retu);

    LOGGER_DEBUG("New msi session: %p ", retu);
    return retu;
}

int msi_kill ( MSISession *session )
{
    if (session == NULL) {
        LOGGER_ERROR("Tried to terminate non-existing session");
        return -1;
    }

    m_callback_msi_packet((struct Messenger *) session->messenger_handle, NULL, NULL);
    pthread_mutex_lock(session->mutex);

    if (session->calls) {
        MSIMessage *msg_end = msi_new_message ( type_request, requ_end );
        
        MSICall* it = get_call(session, session->calls_head);
        for (; it; it = it->next) {
            send_message(it, msg_end, it->friend_id);
            kill_call(it);
        }
        
        free(msg_end);
    }
    
    pthread_mutex_unlock(session->mutex);
    pthread_mutex_destroy(session->mutex);

    LOGGER_DEBUG("Terminated session: %p", session);
    free ( session );
    return 0;
}

int msi_invite ( MSISession *session, MSICall **call, uint32_t friend_id, uint8_t capabilities )
{
    LOGGER_DEBUG("Session: %p Inviting friend: %u", session, friend_id);
    
    if (get_call(session, friend_id) != NULL) {
        LOGGER_ERROR("Already in a call");
        return -1;
    }
    
    *call = new_call ( session, friend_id );

    if ( *call == NULL )
        return -1;
    
    *call->capabilities = capabilities;
    
    MSIMessage *msg_invite = msi_new_message ( type_request, requ_invite );
    
    msg_invite->capabilities.value = capabilities;
    msg_invite->capabilities.exists = 1;
    
    send_message ( *call, msg_invite, friend_id );
    free( msg_invite );

    *call->state = msi_CallRequesting;
    
    LOGGER_DEBUG("Invite sent");
    return 0;
}

int msi_hangup ( MSICall* call )
{
    LOGGER_DEBUG("Session: %p Hanging up call: %u", session, call_index);
    
    MSIMessage *msg_end = msi_new_message ( type_request, requ_end );
    send_message ( call, msg_end, call->friend_id );
    free ( msg_end );
    
    kill_call(call);
    return 0;
}

int msi_answer ( MSICall* call, uint8_t capabilities )
{
    LOGGER_DEBUG("Session: %p Answering call: %u", session, call_index);

    if ( call->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        return -1;
    }
    
    call->capabilities = capabilities;
    
    MSIMessage *msg_starting = msi_new_message ( type_response, resp_starting );
    
    msg_starting->capabilities.value = capabilities;
    msg_starting->capabilities.exists = 1;
    
    send_message ( call, msg_starting, call->friend_id );
    free ( msg_starting );

    return 0;
}

int msi_reject ( MSICall* call )
{
    LOGGER_DEBUG("Session: %p Rejecting call: %u; reason: %s", session, call_index, reason ? reason : "Unknown");

    if ( call->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_reject = msi_new_message ( type_request, requ_reject );
    send_message ( call, msg_reject, call->friend_id );
    free ( msg_reject );

    return 0;
}

int msi_change_csettings( MSICall* call, uint8_t capabilities )
{
    pthread_mutex_lock(session->mutex);

    LOGGER_DEBUG("Changing media on call: %d", call_index);

    MSICall *call = session->calls[call_index];

    if ( call->state != msi_CallActive ) {
        LOGGER_ERROR("Call is not active!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSICSettings *local = &call->csettings_local;

    if (
        local->call_type == csettings->call_type &&
        local->video_bitrate == csettings->video_bitrate &&
        local->max_video_width == csettings->max_video_width &&
        local->max_video_height == csettings->max_video_height &&
        local->audio_bitrate == csettings->audio_bitrate &&
        local->audio_frame_duration == csettings->audio_frame_duration &&
        local->audio_sample_rate == csettings->audio_sample_rate &&
        local->audio_channels == csettings->audio_channels ) {
        LOGGER_ERROR("Call is already set accordingly!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    *local = *csettings;

    MSIMessage *msg_invite = msi_new_message ( type_request, requ_invite );

    msi_msg_set_csettings ( msg_invite, local );
    send_message ( session, call, msg_invite, call->peers[0] );
    free ( msg_invite );

    LOGGER_DEBUG("Request for media change sent");

    pthread_mutex_unlock(session->mutex);

    return 0;
}