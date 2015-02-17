/**  msi.c
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
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
    IDMVFSZ,
    IDMVFPSZ,

} MSIHeaderID;

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
bool exists; \
} MSIHeader##header


GENERIC_HEADER ( Request, MSIRequest );
GENERIC_HEADER ( Response, MSIResponse );
GENERIC_HEADER ( Error, MSIError );
GENERIC_HEADER ( Capabilities, uint8_t );
GENERIC_HEADER ( MVFSZ, uint16_t );
GENERIC_HEADER ( MVFPSZ, uint16_t );


typedef struct {
    MSIHeaderRequest      request;
    MSIHeaderResponse     response;
    MSIHeaderError        error;
    MSIHeaderCapabilities capabilities;
    MSIHeaderMVFSZ        mvfsz;  /* Max video frame size. NOTE: Value must be in network b-order */
    MSIHeaderMVFPSZ       mvfpsz; /* Max video frame piece size. NOTE: Value must be in network b-order */
} MSIMessage;


static int parse_input ( MSIMessage *dest, const uint8_t *data, uint16_t length )
{
    /* Parse raw data received from socket into MSIMessage struct */
    
#define CHECK_SIZE(bytes, constraint, size) \
    if ((constraint -= (2 + size)) < 1) { LOGGER_ERROR("Read over length!"); return -1; } \
    if ( bytes[1] != size ) { LOGGER_ERROR("Invalid data size!"); return -1; }
    
#define CHECK_ENUM_HIGH(bytes, enum_high) /* Assumes size == 1 */ \
    if ( bytes[2] > enum_high ) { LOGGER_ERROR("Failed enum high limit!"); return -1; }
    
#define SET_UINT8(bytes, header) do { \
        header.value = bytes[2]; \
        header.exists = true; \
        bytes += 3; \
    } while(0)

#define SET_UINT16(bytes, header) do { \
        memcpy(&header.value, bytes + 2, 2);\
        header.exists = true; \
        bytes += 4; \
    } while(0)
    
    
    if ( dest == NULL ) {
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
                SET_UINT8(it, dest->request);
                break;
                
            case IDResponse:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, resp_error);
                SET_UINT8(it, dest->response);
                it += 3;
                break;
                
            case IDError:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, msi_ErrUndisclosed);
                SET_UINT8(it, dest->error);
                break;
                
            case IDCapabilities:
                CHECK_SIZE(it, size_constraint, 1);
                SET_UINT8(it, dest->capabilities);
                break;
            
            case IDMVFSZ:
                CHECK_SIZE(it, size_constraint, 2);
                SET_UINT16(it, dest->mvfsz);
                break;
                
            case IDMVFPSZ:
                CHECK_SIZE(it, size_constraint, 2);
                SET_UINT16(it, dest->mvfpsz);
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
#undef SET_UINT8
#undef SET_UINT16
}

static uint8_t *parse_header ( MSIHeaderID id, uint8_t *dest, const void *value, 
                               uint8_t value_len, uint16_t *length )
{
    /* Parse a single header for sending */
    
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



static void call_invoke_callback(MSICall* call, MSICallbackID cb)
{
    if ( call->session->callbacks[cb] ) {
        LOGGER_DEBUG("Invoking callback function: %d", cb);
        call->session->callbacks[cb] ( call->session->agent_handler, call );
    }
}

static int call_send_message ( MSICall *call, const MSIMessage *msg )
{
    /* Parse and send message */
    
    uint8_t parsed [MSI_MAXMSG_SIZE];

    uint8_t *it = parsed;
    uint16_t size = 0;
    
    if (msg->request.exists) {
        uint8_t cast = msg->request.value;
        it = parse_header(IDRequest, it, &cast, 
                          sizeof(cast), &size);
    }
    
    if (msg->response.exists) {
        uint8_t cast = msg->response.value;
        it = parse_header(IDResponse, it, &cast, 
                          sizeof(cast), &size);
    }
    
    if (msg->error.exists) {
        it = parse_header(IDError, it, &msg->error.value, 
                          sizeof(msg->error.value), &size);
    }
    
    if (msg->capabilities.exists) {
        it = parse_header(IDCapabilities, it, &msg->capabilities.value, 
                          sizeof(msg->capabilities.value), &size);
    }
    
    if (msg->mvfsz.exists) {
        it = parse_header(IDMVFSZ, it, &msg->mvfsz.value,
                          sizeof(msg->mvfsz.value), &size);
    }
    
    if (msg->mvfpsz.exists) {
        it = parse_header(IDMVFPSZ, it, &msg->mvfpsz.value,
                          sizeof(msg->mvfpsz.value), &size);
    }
    
    *it = 0;
    size ++;
    
    if ( it == parsed ) {
        LOGGER_WARNING("Parsing message failed; empty message");
        return -1;
    }
    
    if ( m_msi_packet(call->session->messenger_handle, call->friend_id, parsed, size) ) {
        LOGGER_DEBUG("Sent message");
        return 0;
    }

    return -1;
}

static int call_send_error ( MSICall *call, MSIError error )
{
    /* Send error message */
    
    if (!call) {
        LOGGER_WARNING("Cannot handle error on 'null' call");
        return -1;
    }

    LOGGER_DEBUG("Sending error: %d to friend: %d", error, call->friend_id);

    MSIMessage msg_error;
    msg_error.response.exists = true;
    msg_error.response.value = resp_error;
    
    msg_error.error.exists = true;
    msg_error.error.value = error;
    
    call_send_message ( call, &msg_error );
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



static void on_remote_connection_change(Messenger *messenger, int friend_id, uint8_t status, void *session_p)
{
    (void)messenger;
    MSISession *session = session_p;

    switch ( status ) {
        case 0: { /* Went offline */
            MSICall* call = get_call(session, friend_id);
            
            if (call == NULL)
                return;
            
            call_invoke_callback(call, msi_OnPeerTimeout);
            kill_call(call);
        }
        break;

        default:
            break;
    }
}



/********** Request handlers **********/
static int handle_recv_invite ( MSICall *call, const MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'invite' on no call");
        return -1;
    }
    
    MSISession* session = call->session;
    
    LOGGER_DEBUG("Session: %p Handling 'invite' friend: %d", call->session, call->friend_id);

    if (!msg->capabilities.exists) {
        LOGGER_WARNING("Session: %p Invalid capabilities on 'invite'");
        /* TODO send error */
        return -1;
    }
    
    if (!msg->mvfsz.exists) {
        LOGGER_WARNING("Session: %p Invalid mvfsz on 'invite'");
        /* TODO send error */
        return -1;
    }
    
    if (!msg->mvfpsz.exists) {
        LOGGER_WARNING("Session: %p Invalid mvfpsz on 'invite'");
        /* TODO send error */
        return -1;
    }
    
    MSIMessage response;
    response.response.exists = true;
    
    if ( call->state == msi_CallRequesting ) {
        /* The rare glare case.
         * Send starting and wait for starting by the other side.
         * The peer will do the same.
         * When you receive starting from peer send started.
         * Don't notice the app until the start is received.
         */
        
        LOGGER_DEBUG("Glare detected!");
        
        call->peer_capabilities = msg->capabilities;
        
        call->peer_mvfsz = ntohs(msg->mvfsz.value);
        call->peer_mvfpsz = ntohs(msg->mvfpsz.value);
        
        /* Send response */
        response.response.value = resp_starting;
        call_send_message ( call, &response );
        
        return 0;
    } else if ( call->state == msi_CallActive ) {
        /* Changing capabilities.
         * We send starting but no response is expected.
         * WARNING: if start is sent call is terminated with an error
         */
        LOGGER_DEBUG("Peer is changing capabilities");
        
        call->peer_capabilities = msg->capabilities;
        
        call->peer_mvfsz = ntohs(msg->mvfsz.value);
        call->peer_mvfpsz = ntohs(msg->mvfpsz.value);
        
        /* Send response */
        response.response.value = resp_starting;
        call_send_message ( call, &response );
        
        
        call_invoke_callback(call, msi_OnCapabilities);
        return 0;
    }
    
    call->peer_capabilities = msg->capabilities;
    
    call->peer_mvfsz = ntohs(msg->mvfsz.value);
    call->peer_mvfpsz = ntohs(msg->mvfpsz.value);
    
    call->state = msi_CallRequested;
    
    /* Send response */
    response.response.value = resp_ringing;
    call_send_message ( call, &response );
    
    
    call_invoke_callback(call, msi_OnInvite);
    return 0;
}

static int handle_recv_start ( MSICall *call, const MSIMessage *msg )
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
    call_invoke_callback(call, msi_OnStart);
    
    return 0;
}

static int handle_recv_reject ( MSICall *call, const MSIMessage *msg )
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

    call_invoke_callback(call, msi_OnReject);
    kill_call(call);

    return 0;
}

static int handle_recv_end ( MSICall *call, const MSIMessage *msg )
{
    (void)msg;
    
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'end', friend id: %d", call->session, call->friend_id);

    call_invoke_callback(call, msi_OnEnd);
    kill_call ( call );

    return 0;
}

/********** Response handlers **********/
static int handle_recv_ringing ( MSICall *call, const MSIMessage *msg )
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

    call_invoke_callback(call, msi_OnRinging);
    return 0;
}

static int handle_recv_starting ( MSICall *call, const MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Session: %p Handling 'starting' on non-existing call");
        return 0;
    }
    
    if ( call->state == msi_CallActive ) {
        LOGGER_DEBUG("Capabilities change confirmed");
        return 0;
    } else if ( call->state != msi_CallRequested || call->state != msi_CallRequesting ) {
        LOGGER_WARNING("Session: %p Invalid call state on 'starting'");
        /* TODO send error */
        return -1;
    }
    
    if (call->state == msi_CallRequesting) {
        if (!msg->capabilities.exists) {
            LOGGER_WARNING("Session: %p Invalid capabilities on 'starting'");
            /* TODO send error */
            return -1;
        }
        
        if (!msg->mvfsz.exists) {
            LOGGER_WARNING("Session: %p Invalid mvfsz on 'invite'");
            /* TODO send error */
            return -1;
        }
        
        if (!msg->mvfpsz.exists) {
            LOGGER_WARNING("Session: %p Invalid mvfpsz on 'invite'");
            /* TODO send error */
            return -1;
        }
        
        call->peer_capabilities = msg->capabilities.value;
        
        call->peer_mvfsz = ntohs(msg->mvfsz.value);
        call->peer_mvfpsz = ntohs(msg->mvfpsz.value);
        
        call->state = msi_CallActive;
        call_invoke_callback(call, msi_OnStart);
    }
    /* Otherwise it's a glare case so don't start until 'start' is recved */
    
    /* Send start in either case (glare or normal) */
    MSIMessage msg_start;
    msg_start.request.exists = true;
    msg_start.request.value = requ_start;
    call_send_message ( call, &msg_start );
    
    return 0;
}

static int handle_recv_error ( MSICall *call, const MSIMessage *msg )
{
    if ( call == NULL ) {
        LOGGER_WARNING("Handling 'error' on non-existing call!");
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'error' friend id: %d", call->session, call->friend_id );

    call_invoke_callback(call, msi_OnError);

    /* TODO Handle error accordingly */

    return -1;
}

static void handle_msi_packet ( Messenger *messenger, int friend_id, const uint8_t *data, 
                                uint16_t length, void *object )
{
    LOGGER_DEBUG("Got msi message");
    
    /* Unused */
    (void)messenger;

    MSISession *session = object;
    MSIMessage msg;

    if ( parse_input ( &msg, data, length ) == -1 ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }
    
    pthread_mutex_lock(session->mutex);

    MSICall *call = get_call(session, friend_id);
    
    if (call == NULL) {
        if (msg.request != requ_invite) {
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
    if ( msg.request.exists ) { /* Handle request */
        switch (msg.request.value) {
            case requ_invite:
                rc = handle_recv_invite ( call, &msg );
                break;

            case requ_start:
                rc = handle_recv_start ( call, &msg );
                break;

            case requ_reject:
                rc = handle_recv_reject ( call, &msg );
                break;

            case requ_end:
                rc = handle_recv_end ( call, &msg );
                break;
        }
    } else if ( msg.response.exists ) { /* Handle response */
        switch (msg.response.value) {
            case resp_ringing:
                rc = handle_recv_ringing ( call, &msg );
                break;

            case resp_starting:
                rc = handle_recv_starting ( call, &msg );
                break;

            case resp_error:
                rc = handle_recv_error ( call, &msg );
                break;
        }
    } else {
        LOGGER_WARNING("Invalid message: no resp nor requ headers");
        /* TODO send error */
        rc = -1;
    }
    
    if (rc == -1)
        kill_call(call);
    
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

    m_callback_msi_packet(messenger, handle_msi_packet, retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, on_remote_connection_change, retu);

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
        MSIMessage msg_end;
        msg_end.request.exists = true;
        msg_end.request.value = requ_end;
        
        MSICall* it = get_call(session, session->calls_head);
        for (; it; it = it->next) {
            call_send_message(it, &msg_end);
            kill_call(it); /* This will eventually free session->calls */
        }
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
    
    *call->self_capabilities = capabilities;
    
    MSIMessage msg_invite;
    msg_invite.request.exists = true;
    msg_invite.request.value = requ_invite;
    
    msg_invite.capabilities.exists = true;
    msg_invite.capabilities.value = capabilities;
    
    msg_invite.mvfsz.exists = true;
    msg_invite.mvfsz.value = htons(D_MVFSZ);
    
    msg_invite.mvfpsz.exists = true;
    msg_invite.mvfpsz.value = htons(D_MVFPSZ);
    
    call_send_message ( *call, &msg_invite );

    *call->state = msi_CallRequesting;
    
    LOGGER_DEBUG("Invite sent");
    return 0;
}

int msi_hangup ( MSICall* call )
{
    LOGGER_DEBUG("Session: %p Hanging up call: %u", session, call_index);
    
    MSIMessage msg_end;
    msg_end.request.exists = true;
    msg_end.request.value = requ_end;
    call_send_message ( call, &msg_end );
    
    kill_call(call);
    return 0;
}

int msi_answer ( MSICall* call, uint8_t capabilities )
{
    LOGGER_DEBUG("Session: %p Answering call from: %u", call->session, call->friend_id);

    if ( call->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        return -1;
    }
    
    call->self_capabilities = capabilities;
    
    MSIMessage msg_starting;
    msg_starting.response.exists = true;
    msg_starting.response.value = resp_starting;
    
    msg_starting.capabilities.exists = true;
    msg_starting.capabilities.value = capabilities;
    
    msg_starting.mvfsz.exists = true;
    msg_starting.mvfsz.value = htons(D_MVFSZ);
    
    msg_starting.mvfpsz.exists = true;
    msg_starting.mvfpsz.value = htons(D_MVFPSZ);
    
    call_send_message ( call, &msg_starting );

    return 0;
}

int msi_reject ( MSICall* call )
{
    LOGGER_DEBUG("Session: %p Rejecting call: %u; reason: %s", session, call_index, reason ? reason : "Unknown");

    if ( call->state != msi_CallRequested ) {
        LOGGER_ERROR("Call is in invalid state!");
        return -1;
    }
    
    MSIMessage msg_reject;
    msg_reject.request.exists = true;
    msg_reject.request.value = requ_reject;
    
    call_send_message ( call, &msg_reject );

    return 0;
}

int msi_change_csettings( MSICall* call, uint8_t capabilities )
{
    call->self_capabilities = capabilities;
    
    MSIMessage msg_invite;
    msg_invite.request.exists = true;
    msg_invite.request.value = requ_invite;
    
    msg_invite.capabilities.exists = true;
    msg_invite.capabilities.value = capabilities;
    
    call_send_message ( *call, &msg_invite );
    
    return 0;
}