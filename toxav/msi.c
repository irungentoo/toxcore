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
    IDReason,
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
    requ_cancel,
    requ_reject,
    requ_end,
} MSIRequest;

typedef enum {
    resp_ringing,
    resp_starting,
    resp_ending,
    resp_error,
} MSIResponse;

typedef enum {
    res_undisclosed,
} MSIReason;

typedef enum {
    cap_saudio, /* sending audio */
    cap_svideo, /* sending video */
    cap_raudio, /* receiving audio */
    cap_rvideo, /* receiving video */
} MSICapabilities;

#define GENERIC_HEADER(header, val_type) \
typedef struct { \
val_type value; \
_Bool exists; \
} MSIHeader##header;


GENERIC_HEADER ( Request, MSIRequest )
GENERIC_HEADER ( Response, MSIResponse )
GENERIC_HEADER ( Reason, MSIReason )
GENERIC_HEADER ( Capabilities, MSICapabilities )


typedef struct {
    MSIHeaderRequest      request;
    MSIHeaderResponse     response;
    MSIHeaderReason       reason;
    MSIHeaderCapabilities capabilities;
} MSIMessage;


static void invoke_callback(MSISession *s, int32_t c, MSICallbackID i)
{
    if ( s->callbacks[i] ) {
        LOGGER_DEBUG("Invoking callback function: %d", i);
        s->callbacks[i] ( s->agent_handler, c );
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
#define PARSE_HEADER(bytes, header, constraint, enum_high_limit) do {\
        if ((constraint -= 3) < 1) { \
            LOGGER_ERROR("Read over length!"); \
            return -1; \
        } \
        \
        if ( bytes[1] != 1 ) { \
            LOGGER_ERROR("Invalid data size!"); \
            return -1; \
        } \
        \
        if ( bytes[2] > enum_high_limit ) { \
            LOGGER_ERROR("Failed enum high limit!"); \
            return -1; \
        } \
        \
        header.value = bytes[2]; \
        header.exists = 1; \
        bytes += 3; \
    } while(0)


    if ( msg == NULL ) {
        LOGGER_ERROR("Could not parse message: no storage!");
        return -1;
    }

    if ( data[length - 1] ) { /* End byte must have value 0 */
        LOGGER_ERROR("Invalid end byte");
        return -1;
    }

    const uint8_t *it = data;
    int size_constraint = length;

    while ( *it ) {/* until end byte is hit */
        switch (*it) {
            case IDRequest:
                PARSE_HEADER(it, msg->request, size_constraint, requ_end);
                break;
                
            case IDResponse:
                PARSE_HEADER(it, msg->response, size_constraint, resp_error);
                it += 3;
                break;
                
            case IDReason:
                PARSE_HEADER(it, msg->reason, size_constraint, res_undisclosed);
                break;
                
            case IDCapabilities:
                PARSE_HEADER(it, msg->capabilities, size_constraint, requ_end);
                break;
                
            default:
                LOGGER_ERROR("Invalid id byte");
                return -1;
                break;
        }
    }

    return 0;

#undef PARSE_HEADER
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

    if (msg->reason.exists) {
        it = prepare_header(IDReason, it, &msg->reason.value, sizeof(msg->reason.value), &size);
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

static int send_error ( MSICall *call, MSIReason reason, uint32_t to )
{
    if (!call) {
        LOGGER_WARNING("Cannot handle error on 'null' call");
        return -1;
    }

    LOGGER_DEBUG("Sending error: %d on call: %d", reason, call->call_idx);

    MSIMessage *msg_error = msi_new_message ( type_response, resp_error );
    
    if (!msg_error)
        return -1;
    
    msg_error->reason.exists = 1;
    msg_error->reason.value = reason;
    
    send_message ( call, msg_error, to );
    free ( msg_error );

    return 0;
}



static MSICall *init_call ( MSISession *session, int peers, int ringing_timeout )
{
    
}

static int terminate_call ( MSISession *session, MSICall *call )
{
    if ( !call ) {
        LOGGER_WARNING("Tried to terminate non-existing call!");
        return -1;
    }

    session->calls[call->call_idx] = NULL;

    LOGGER_DEBUG("Terminated call id: %d", call->call_idx);

    free ( call->csettings_peer );
    free ( call->peers );
    free ( call );

    return 0;
}

static void handle_remote_connection_change(Messenger *messenger, int friend_num, uint8_t status, void *session_p)
{
    (void)messenger;
    MSISession *session = session_p;

    switch ( status ) {
        case 0: { /* Went offline */
            int32_t j = 0;

            for ( ; j < session->max_calls; j ++ ) {

                if ( !session->calls[j] ) continue;

                uint16_t i = 0;

                for ( ; i < session->calls[j]->peer_count; i ++ )
                    if ( session->calls[j]->peers[i] == (uint32_t)friend_num ) {
                        invoke_callback(session, j, msi_OnPeerTimeout);
                        terminate_call(session, session->calls[j]);
                        LOGGER_DEBUG("Remote: %d timed out!", friend_num);
                        return; /* TODO: On group calls change behaviour */
                    }
            }
        }
        break;

        default:
            break;
    }
}

/********** Request handlers **********/
static int handle_recv_invite ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'invite' on call: %d", session, call ? call->call_idx : -1);


    if (!msg->csettings.exists) {/**/
        LOGGER_WARNING("Peer sent invalid codec settings!");
        send_error ( session, call, error_no_callid, msg->friend_id );
        return 0;
    }

    if ( call ) {
        if ( call->peers[0] == (uint32_t)msg->friend_id ) {
            if (call->state == msi_CallRequesting) {
                /* The glare case. A calls B when at the same time
                 * B calls A. Who has advantage is set bey calculating
                 * 'bigger' Call id and then that call id is being used in
                 * future. User with 'bigger' Call id has the advantage
                 * as in he will wait the response from the other.
                 */
                LOGGER_DEBUG("Glare case; Peer: %d", call->peers[0]);

                if ( call_id_bigger (call->id, msg->callid.value) == 1 ) { /* Peer has advantage */

                    /* Terminate call; peer will timeout(call) if call initialization fails */
                    terminate_call(session, call);

                    call = init_call ( session, 1, 0 );

                    if ( !call ) {
                        LOGGER_ERROR("Starting call");
                        return 0;
                    }

                } else {
                    return 0; /* Wait for ringing from peer */
                }
            } else if (call->state == msi_CallActive) {
                /* Request for media change; call callback and send starting response */
                if (flush_peer_csettings(call, msg, 0) != 0) { /**/
                    LOGGER_WARNING("Peer sent invalid csetting!");
                    send_error ( session, call, error_no_callid, msg->friend_id );
                    return 0;
                }

                LOGGER_DEBUG("Set new call type: %s", call->csettings_peer[0].call_type == msi_TypeAudio ? "audio" : "video");
                send_reponse(session, call, resp_starting, msg->friend_id);
                invoke_callback(session, call->call_idx, msi_OnPeerCSChange);
                return 1;
            }
        } else {
            send_error ( session, call, error_busy, msg->friend_id ); /* TODO: Ugh*/
            terminate_call(session, call);
            return 0;
        }
    } else {
        call = init_call ( session, 1, 0 );

        if ( !call ) {
            LOGGER_ERROR("Starting call");
            return 0;
        }
    }

    if ( !msg->callid.exists ) {
        send_error ( session, call, error_no_callid, msg->friend_id );
        terminate_call(session, call);
        return 0;
    }

    memcpy ( call->id, msg->callid.value, sizeof(msg->callid.value) );
    call->state = msi_CallRequested;

    add_peer( call, msg->friend_id);
    flush_peer_csettings ( call, msg, 0 );
    send_reponse(session, call, resp_ringing, msg->friend_id);
    invoke_callback(session, call->call_idx, msi_OnInvite);

    return 1;
}

static int handle_recv_start ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    (void)msg;

    LOGGER_DEBUG("Session: %p Handling 'start' on call: %d, friend id: %d", session, call->call_idx, msg->friend_id );

    call->state = msi_CallActive;
    invoke_callback(session, call->call_idx, msi_OnStart);
    return 1;
}

static int handle_recv_reject ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'reject' on call: %u", session, call->call_idx);

    invoke_callback(session, call->call_idx, msi_OnReject);

    send_reponse(session, call, resp_ending, msg->friend_id);
    terminate_call(session, call);

    return 1;
}

static int handle_recv_cancel ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    (void)msg;

    LOGGER_DEBUG("Session: %p Handling 'cancel' on call: %u", session, call->call_idx);

    invoke_callback(session, call->call_idx, msi_OnCancel);
    terminate_call ( session, call );

    return 1;
}

static int handle_recv_end ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'end' on call: %d", session, call->call_idx);

    invoke_callback(session, call->call_idx, msi_OnEnd);
    send_reponse(session, call, resp_ending, msg->friend_id);
    terminate_call ( session, call );

    return 1;
}

/********** Response handlers **********/
static int handle_recv_ringing ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    (void)msg;

    if ( call->ringing_timer_id ) {
        LOGGER_WARNING("Call already ringing");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'ringing' on call: %d", session, call->call_idx );

    call->ringing_timer_id = timer_alloc
                             ( session, handle_timeout, call->call_idx, call->ringing_tout_ms );
    invoke_callback(session, call->call_idx, msi_OnRinging);
    return 1;
}
static int handle_recv_starting ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'starting' on non-existing call");
        return 0;
    }

    if ( call->state == msi_CallActive ) { /* Change media */

        LOGGER_DEBUG("Session: %p Changing media on call: %d", session, call->call_idx );

        invoke_callback(session, call->call_idx, msi_OnSelfCSChange);

    } else if ( call->state == msi_CallRequesting ) {
        LOGGER_DEBUG("Session: %p Handling 'starting' on call: %d", session, call->call_idx );

        call->state = msi_CallActive;

        MSIMessage *msg_start = msi_new_message ( type_request, requ_start );
        send_message ( session, call, msg_start, msg->friend_id );
        free ( msg_start );


        flush_peer_csettings ( call, msg, 0 );

        /* This is here in case of glare */
        timer_release(session->timer_handler, call->ringing_timer_id);
        invoke_callback(session, call->call_idx, msi_OnStart);
    } else {
        LOGGER_ERROR("Invalid call state");
        terminate_call(session, call );
        return 0;
    }

    return 1;
}
static int handle_recv_ending ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    (void)msg;

    LOGGER_DEBUG("Session: %p Handling 'ending' on call: %d", session, call->call_idx );

    invoke_callback(session, call->call_idx, msi_OnEnd);
    terminate_call ( session, call );

    return 1;
}
static int handle_recv_error ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Handling 'error' on non-existing call!");
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'error' on call: %d", session, call->call_idx );

    invoke_callback(session, call->call_idx, msi_OnEnd);

    /* Handle error accordingly */
    if ( msg->reason.exists ) {
        /* TODO */
    }

    terminate_call ( session, call );

    return 1;
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
static void msi_handle_packet ( Messenger *messenger, int source, const uint8_t *data, uint16_t length, void *object )
{
    LOGGER_DEBUG("Got msi message");
    /* Unused */
    (void)messenger;

    MSISession *session = object;
    MSIMessage *msg;

    if ( !length ) {
        LOGGER_WARNING("Length param negative");
        return;
    }

    msg = parse_in ( data, length );

    if ( !msg ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }

    pthread_mutex_lock(session->mutex);

    /* Find what call */
    MSICall *call = NULL;
    
    /* Now handle message */

    if ( msg->request.exists ) { /* Handle request */

        switch (msg->request.value) {
            case requ_invite:
                handle_recv_invite ( session, call, msg );
                break;

            case requ_start:
                handle_recv_start ( session, call, msg );
                break;

            case requ_cancel:
                handle_recv_cancel ( session, call, msg );
                break;

            case requ_reject:
                handle_recv_reject ( session, call, msg );
                break;

            case requ_end:
                handle_recv_end ( session, call, msg );
                break;
        }

    } else if ( msg->response.exists ) { /* Handle response */
        
        switch (msg->response.value) {
            case resp_ringing:
                handle_recv_ringing ( session, call, msg );
                break;

            case resp_starting:
                handle_recv_starting ( session, call, msg );
                break;

            case resp_ending:
                handle_recv_ending ( session, call, msg );
                break;

            case resp_error:
                handle_recv_error ( session, call, msg );
                break;
        }

    } else {
        LOGGER_WARNING("Invalid message: no resp nor requ headers");
    }

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
        goto error;
    }

    retu->messenger_handle = messenger;

    m_callback_msi_packet(messenger, msi_handle_packet, retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, retu);

    LOGGER_DEBUG("New msi session: %p ", retu);
    return retu;

error:

    if (retu->timer_handler) {
        free(((TimerHandler *)retu->timer_handler)->timers);
        free(retu->timer_handler);
    }

    free(retu->calls);
    free(retu);
    return NULL;
}

int msi_kill ( MSISession *session )
{
    if (session == NULL) {
        LOGGER_ERROR("Tried to terminate non-existing session");
        return -1;
    }

    m_callback_msi_packet((struct Messenger *) session->messenger_handle, NULL, NULL);
    pthread_mutex_lock(session->mutex);

    /* Cancel active calls */
    int32_t idx = 0;

    for (; idx < session->max_calls; idx ++) if ( session->calls[idx] ) {
            /* Cancel all? */
            uint16_t _it = 0;
            /*for ( ; _it < session->calls[idx]->peer_count; _it++ )
             * FIXME: will not work on multiple peers, must cancel call for all peers
             */
            msi_cancel ( session, idx, session->calls[idx]->peers [_it], "MSI session terminated!" );
        }

    free ( session->calls );
    pthread_mutex_unlock(session->mutex);
    pthread_mutex_destroy(session->mutex);

    LOGGER_DEBUG("Terminated session: %p", session);
    free ( session );
    return 0;
}

int msi_invite ( MSISession *session,
                 int32_t *call_index,
                 const MSICSettings *csettings,
                 uint32_t rngsec,
                 uint32_t friend_id )
{
    pthread_mutex_lock(session->mutex);

    LOGGER_DEBUG("Session: %p Inviting friend: %u", session, friend_id);


    int i = 0;

    for (; i < session->max_calls; i ++)
        if (session->calls[i] && session->calls[i]->peers[0] == friend_id) {
            LOGGER_ERROR("Already in a call with friend %d", friend_id);
            pthread_mutex_unlock(session->mutex);
            return msi_ErrorAlreadyInCallWithPeer;
        }


    MSICall *call = init_call ( session, 1, rngsec ); /* Just one peer for now */

    if ( !call ) {
        pthread_mutex_unlock(session->mutex);
        LOGGER_ERROR("Cannot handle more calls");
        return msi_ErrorReachedCallLimit;
    }

    *call_index = call->call_idx;

    t_randomstr ( call->id, sizeof(call->id) );

    add_peer ( call, friend_id );

    call->csettings_local = *csettings;

    MSIMessage *msg_invite = msi_new_message ( type_request, requ_invite );

    msi_msg_set_csettings(msg_invite, csettings);
    send_message ( session, call, msg_invite, friend_id );
    free( msg_invite );

    call->state = msi_CallRequesting;

    call->request_timer_id = timer_alloc ( session, handle_timeout, call->call_idx, m_deftout );

    LOGGER_DEBUG("Invite sent");

    pthread_mutex_unlock(session->mutex);

    return 0;
}

int msi_hangup ( MSISession *session, int32_t call_index )
{
    pthread_mutex_lock(session->mutex);
    LOGGER_DEBUG("Session: %p Hanging up call: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

    if ( session->calls[call_index]->state != msi_CallActive ) {
        LOGGER_ERROR("Call is not active!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_end = msi_new_message ( type_request, requ_end );

    /* hangup for each peer */
    int it = 0;

    for ( ; it < session->calls[call_index]->peer_count; it ++ )
        send_message ( session, session->calls[call_index], msg_end, session->calls[call_index]->peers[it] );

    session->calls[call_index]->state = msi_CallOver;

    free ( msg_end );

    session->calls[call_index]->request_timer_id =
        timer_alloc ( session, handle_timeout, call_index, m_deftout );

    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_answer ( MSISession *session, int32_t call_index, const MSICSettings *csettings )
{
    pthread_mutex_lock(session->mutex);
    LOGGER_DEBUG("Session: %p Answering call: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

    if ( session->calls[call_index]->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_starting = msi_new_message ( type_response, resp_starting );

    session->calls[call_index]->csettings_local = *csettings;

    msi_msg_set_csettings(msg_starting, csettings);

    send_message ( session, session->calls[call_index], msg_starting, session->calls[call_index]->peers[0] );
    free ( msg_starting );

    session->calls[call_index]->state = msi_CallActive;

    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_cancel ( MSISession *session, int32_t call_index, uint32_t peer, const char *reason )
{
    pthread_mutex_lock(session->mutex);
    LOGGER_DEBUG("Session: %p Canceling call: %u; reason: %s", session, call_index, reason ? reason : "Unknown");

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

    if ( session->calls[call_index]->state != msi_CallRequesting ) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_cancel = msi_new_message ( type_request, requ_cancel );

    /* FIXME */
#if 0

    if ( reason && strlen(reason) < sizeof(MSIReasonStrType) ) {
        MSIReasonStrType reason_cast;
        memset(reason_cast, '\0', sizeof(MSIReasonStrType));
        memcpy(reason_cast, reason, strlen(reason));
        msi_msg_set_reason(msg_cancel, reason_cast);
    }

#else
    (void)reason;

#endif

    send_message ( session, session->calls[call_index], msg_cancel, peer );
    free ( msg_cancel );

    terminate_call ( session, session->calls[call_index] );
    pthread_mutex_unlock(session->mutex);

    return 0;
}

int msi_reject ( MSISession *session, int32_t call_index, const char *reason )
{
    pthread_mutex_lock(session->mutex);
    LOGGER_DEBUG("Session: %p Rejecting call: %u; reason: %s", session, call_index, reason ? reason : "Unknown");

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

    if ( session->calls[call_index]->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_reject = msi_new_message ( type_request, requ_reject );

    /* FIXME */
#if 0

    if ( reason && strlen(reason) < sizeof(MSIReasonStrType) ) {
        MSIReasonStrType reason_cast;
        memset(reason_cast, '\0', sizeof(MSIReasonStrType));
        memcpy(reason_cast, reason, strlen(reason));
        msi_msg_set_reason(msg_reject, reason_cast);
    }

#else
    (void)reason;

#endif

    send_message ( session, session->calls[call_index], msg_reject,
                   session->calls[call_index]->peers[session->calls[call_index]->peer_count - 1] );
    free ( msg_reject );

    session->calls[call_index]->state = msi_CallOver;
    session->calls[call_index]->request_timer_id =
        timer_alloc ( session, handle_timeout, call_index, m_deftout );

    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_stopcall ( MSISession *session, int32_t call_index )
{
    pthread_mutex_lock(session->mutex);
    LOGGER_DEBUG("Session: %p Stopping call index: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

    /* just terminate it */

    terminate_call ( session, session->calls[call_index] );

    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_change_csettings(MSISession *session, int32_t call_index, const MSICSettings *csettings)
{
    pthread_mutex_lock(session->mutex);

    LOGGER_DEBUG("Changing media on call: %d", call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorNoCall;
    }

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

void msi_do(MSISession *session)
{
    pthread_mutex_lock(session->mutex);

    TimerHandler *timer = session->timer_handler;

    uint64_t time = current_time_monotonic();

    while ( timer->timers[0] && timer->timers[0]->timeout < time ) {
        LOGGER_DEBUG("Executing timer assigned at: %d", timer->timers[0]->timeout);

        int id = timer->timers[0]->id;
        timer->timers[0]->func(timer->timers[0]);

        /* In case function has released timer */
        if (timer->timers[0] && timer->timers[0]->id == id)
            timer_release(timer, id);
    }

    pthread_mutex_unlock(session->mutex);
}
