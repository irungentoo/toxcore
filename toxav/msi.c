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

typedef uint8_t MSIRawCSettingsType[23];

typedef enum {
    IDRequest = 1,
    IDResponse,
    IDReason,
    IDCallId,
    IDCSettings,

} MSIHeaderID;

typedef enum {
    TypeRequest,
    TypeResponse,

} MSIMessageType;

typedef enum {
    invite,
    start,
    cancel,
    reject,
    end,

} MSIRequest;

typedef enum {
    ringing,
    starting,
    ending,
    error

} MSIResponse;


#define GENERIC_HEADER(header, val_type) \
typedef struct _MSIHeader##header { \
val_type value; \
_Bool exists; \
} MSIHeader##header;


GENERIC_HEADER ( Request, MSIRequest )
GENERIC_HEADER ( Response, MSIResponse )
GENERIC_HEADER ( CallId, MSICallIDType )
GENERIC_HEADER ( Reason, MSIReasonStrType )
GENERIC_HEADER ( CSettings, MSIRawCSettingsType )


typedef struct _MSIMessage {

    MSIHeaderRequest   request;
    MSIHeaderResponse  response;
    MSIHeaderReason    reason;
    MSIHeaderCallId    callid;
    MSIHeaderCSettings csettings;

    int friend_id;

} MSIMessage;


static void invoke_callback(MSISession *s, int32_t c, MSICallbackID i)
{
    if ( s->callbacks[i].first ) {
        LOGGER_DEBUG("Invoking callback function: %d", i);

        s->callbacks[i].first( s->agent_handler, c, s->callbacks[i].second );
    }
}

/**
 * Parse raw 'data' received from socket into MSIMessage struct.
 * Every message has to have end value of 'end_byte' or _undefined_ behavior
 * occures. The best practice is to check the end of the message at the handle_packet.
 */
static int parse_raw_data ( MSIMessage *msg, const uint8_t *data, uint16_t length )
{

#define FAIL_CONSTRAINT(constraint, wanted) if ((constraint -= wanted) < 1) { LOGGER_ERROR("Read over length!"); return -1; }
#define FAIL_SIZE(byte, valid) if ( byte != valid ) { LOGGER_ERROR("Invalid data size!"); return -1; }
#define FAIL_LIMITS(byte, high) if ( byte > high ) { LOGGER_ERROR("Failed limit!"); return -1; }

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
                FAIL_CONSTRAINT(size_constraint, 3);
                FAIL_SIZE(it[1], 1);
//                 FAIL_LIMITS(it[2], invite, end);
                FAIL_LIMITS(it[2], end);
                msg->request.value = it[2];
                it += 3;
                msg->request.exists = 1;
                break;

            case IDResponse:
                FAIL_CONSTRAINT(size_constraint, 3);
                FAIL_SIZE(it[1], 1);
//                 FAIL_LIMITS(it[2], ringing, error);
                FAIL_LIMITS(it[2], error);
                msg->response.value = it[2];
                it += 3;
                msg->response.exists = 1;
                break;

            case IDCallId:
                FAIL_CONSTRAINT(size_constraint, sizeof(MSICallIDType) + 2);
                FAIL_SIZE(it[1], sizeof(MSICallIDType));
                memcpy(msg->callid.value, it + 2, sizeof(MSICallIDType));
                it += sizeof(MSICallIDType) + 2;
                msg->callid.exists = 1;
                break;

            case IDReason:
                FAIL_CONSTRAINT(size_constraint, sizeof(MSIReasonStrType) + 2);
                FAIL_SIZE(it[1], sizeof(MSIReasonStrType));
                memcpy(msg->reason.value, it + 2, sizeof(MSIReasonStrType));
                it += sizeof(MSIReasonStrType) + 2;
                msg->reason.exists = 1;
                break;

            case IDCSettings:
                FAIL_CONSTRAINT(size_constraint, sizeof(MSIRawCSettingsType) + 2);
                FAIL_SIZE(it[1], sizeof(MSIRawCSettingsType));
                memcpy(msg->csettings.value, it + 2, sizeof(MSIRawCSettingsType));
                it += sizeof(MSIRawCSettingsType) + 2;
                msg->csettings.exists = 1;
                break;

            default:
                LOGGER_ERROR("Invalid id byte");
                return -1;
                break;
        }
    }

    return 0;
}

/**
 * Create the message.
 */
MSIMessage *msi_new_message ( MSIMessageType type, const uint8_t type_value )
{
    MSIMessage *retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( retu == NULL ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if ( type == TypeRequest ) {
        retu->request.exists = 1;
        retu->request.value = type_value;

    } else {
        retu->response.exists = 1;
        retu->response.value = type_value;
    }

    return retu;
}


/**
 * Parse data from handle_packet.
 */
MSIMessage *parse_recv ( const uint8_t *data, uint16_t length )
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
uint8_t *format_output ( uint8_t *dest,
                         MSIHeaderID id,
                         const void *value,
                         uint8_t value_len,
                         uint16_t *length )
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
 * Parse MSIMessage to send.
 */
uint16_t parse_send ( MSIMessage *msg, uint8_t *dest )
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
        it = format_output(it, IDRequest, &cast, 1, &size);
    }

    if (msg->response.exists) {
        uint8_t cast = msg->response.value;
        it = format_output(it, IDResponse, &cast, 1, &size);
    }

    if (msg->callid.exists) {
        it = format_output(it, IDCallId, &msg->callid.value, sizeof(msg->callid.value), &size);
    }

    if (msg->reason.exists) {
        it = format_output(it, IDReason, &msg->reason.value, sizeof(msg->reason.value), &size);
    }

    if (msg->csettings.exists) {
        it = format_output(it, IDCSettings, &msg->csettings.value, sizeof(msg->csettings.value), &size);
    }

    *it = 0;
    size ++;

    return size;
}

void msi_msg_set_reason ( MSIMessage *msg, const MSIReasonStrType value )
{
    if ( !msg ) return;

    msg->reason.exists = 1;
    memcpy(msg->reason.value, value, sizeof(MSIReasonStrType));
}

void msi_msg_set_callid ( MSIMessage *msg, const MSICallIDType value )
{
    if ( !msg ) return;

    msg->callid.exists = 1;
    memcpy(msg->callid.value, value, sizeof(MSICallIDType));
}

void msi_msg_set_csettings ( MSIMessage *msg, const MSICSettings *value )
{
    if ( !msg ) return;

    msg->csettings.exists = 1;

    msg->csettings.value[0] = value->call_type;
    uint8_t *iter = msg->csettings.value + 1;

    /* Video bitrate */
    uint32_t lval = htonl(value->video_bitrate);
    memcpy(iter, &lval, 4);
    iter += 4;

    /* Video max width */
    uint16_t sval = htons(value->max_video_width);
    memcpy(iter, &sval, 2);
    iter += 2;

    /* Video max height */
    sval = htons(value->max_video_height);
    memcpy(iter, &sval, 2);
    iter += 2;

    /* Audio bitrate */
    lval = htonl(value->audio_bitrate);
    memcpy(iter, &lval, 4);
    iter += 4;

    /* Audio frame duration */
    sval = htons(value->audio_frame_duration);
    memcpy(iter, &sval, 2);
    iter += 2;

    /* Audio sample rate */
    lval = htonl(value->audio_sample_rate);
    memcpy(iter, &lval, 4);
    iter += 4;

    /* Audio channels */
    lval = htonl(value->audio_channels);
    memcpy(iter, &lval, 4);
}

void msi_msg_get_csettings ( MSIMessage *msg, MSICSettings *dest )
{
    if ( !msg || !dest || !msg->csettings.exists ) return;

    dest->call_type = msg->csettings.value[0];
    uint8_t *iter = msg->csettings.value + 1;

    memcpy(&dest->video_bitrate, iter, 4);
    iter += 4;
    dest->video_bitrate = ntohl(dest->video_bitrate);

    memcpy(&dest->max_video_width, iter, 2);
    iter += 2;
    dest->max_video_width = ntohs(dest->max_video_width);

    memcpy(&dest->max_video_height, iter, 2);
    iter += 2;
    dest->max_video_height = ntohs(dest->max_video_height);

    memcpy(&dest->audio_bitrate, iter, 4);
    iter += 4;
    dest->audio_bitrate = ntohl(dest->audio_bitrate);

    memcpy(&dest->audio_frame_duration, iter, 2);
    iter += 2;
    dest->audio_frame_duration = ntohs(dest->audio_frame_duration);

    memcpy(&dest->audio_sample_rate, iter, 4);
    iter += 4;
    dest->audio_sample_rate = ntohl(dest->audio_sample_rate);

    memcpy(&dest->audio_channels, iter, 4);
    dest->audio_channels = ntohl(dest->audio_channels);
}

typedef struct _Timer {
    void (*func)(struct _Timer *);
    uint64_t timeout;
    MSISession *session;
    int call_idx;
    int id;

} Timer;

typedef struct _TimerHandler {
    Timer **timers;

    uint32_t max_capacity;
    uint32_t size;
} TimerHandler;


static int timer_alloc (MSISession *session , void (*func)(Timer *), int call_idx, uint32_t timeout)
{
    static int timer_id;
    TimerHandler *timer_handler = session->timer_handler;

    uint32_t i = 0;

    for (; i < timer_handler->max_capacity && timer_handler->timers[i]; i ++);

    if (i == timer_handler->max_capacity) {
        LOGGER_WARNING("Maximum capacity reached!");
        return -1;
    }

    Timer *timer = timer_handler->timers[i] = calloc(sizeof(Timer), 1);

    if (timer == NULL) {
        LOGGER_ERROR("Failed to allocate timer!");
        return -1;
    }

    timer_handler->size ++;

    timer->func = func;
    timer->session = session;
    timer->call_idx = call_idx;
    timer->timeout = timeout + current_time_monotonic(); /* In ms */
    ++timer_id;
    timer->id = timer_id;

    /* reorder */
    if (i) {
        int64_t j = i - 1;

        for (; j >= 0 && timeout < timer_handler->timers[j]->timeout; j--) {
            Timer *tmp = timer_handler->timers[j];
            timer_handler->timers[j] = timer;
            timer_handler->timers[j + 1] = tmp;
        }
    }

    LOGGER_DEBUG("Allocated timer index: %ull timeout: %ull, current size: %ull", i, timeout, timer_handler->size);
    return timer->id;
}

static int timer_release ( TimerHandler *timers_container, int id)
{
    Timer **timed_events = timers_container->timers;

    uint32_t i;
    int rc = -1;

    for (i = 0; i < timers_container->max_capacity; ++i) {
        if (timed_events[i] && timed_events[i]->id == id) {
            rc = i;
            break;
        }
    }

    if (rc == -1) {
        LOGGER_WARNING("No event with id: %d", id);
        return -1;
    }

    free(timed_events[rc]);

    timed_events[rc] = NULL;

    i = rc + 1;

    for (; i < timers_container->max_capacity && timed_events[i]; i ++) {
        timed_events[i - 1] = timed_events[i];
        timed_events[i] = NULL;
    }

    timers_container->size--;

    LOGGER_DEBUG("Popped id: %d, current size: %ull ", id, timers_container->size);
    return 0;
}

/**
 * Generate _random_ alphanumerical string.
 */
static void t_randomstr ( uint8_t *str, uint32_t size )
{
    if (str == NULL) {
        LOGGER_DEBUG("Empty destination!");
        return;
    }

    static const uint8_t _bytes[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    uint32_t _it = 0;

    for ( ; _it < size; _it++ ) {
        str[_it] = _bytes[ random_int() % 61 ];
    }
}

/* TODO: it would be nice to actually have some sane error codes */
typedef enum {
    error_none,
    error_deadcall,      /* has call id but it's from old call */
    error_id_mismatch,   /* non-existing call */

    error_no_callid,     /* not having call id */
    error_no_call,       /* no call in session */
    error_no_crypto_key, /* no crypto key */

    error_busy

} MSICallError;          /* Error codes */


/**
 * Stringify error code.
 */
static const uint8_t *stringify_error ( MSICallError error_code )
{
    static const uint8_t *strings[] = {
        ( uint8_t *) "",
        ( uint8_t *) "Using dead call",
        ( uint8_t *) "Call id not set to any call",
        ( uint8_t *) "Call id not available",
        ( uint8_t *) "No active call in session",
        ( uint8_t *) "No Crypto-key set",
        ( uint8_t *) "Callee busy"
    };

    return strings[error_code];
}

static int send_message ( MSISession *session, MSICall *call, MSIMessage *msg, uint32_t to )
{
    msi_msg_set_callid ( msg, call->id );

    uint8_t msg_string_final [MSI_MAXMSG_SIZE];
    uint16_t length = parse_send ( msg, msg_string_final );

    if (!length) {
        LOGGER_WARNING("Parsing message failed; nothing sent!");
        return -1;
    }

    if ( m_msi_packet(session->messenger_handle, to, msg_string_final, length) ) {
        LOGGER_DEBUG("Sent message");
        return 0;
    }

    return -1;
}

static int send_reponse ( MSISession *session, MSICall *call, MSIResponse response, uint32_t to )
{
    MSIMessage *msg = msi_new_message ( TypeResponse, response );
    int ret = send_message ( session, call, msg, to );
    free ( msg );
    return ret;
}

static int send_error ( MSISession *session, MSICall *call, MSICallError errid, uint32_t to )
{
    if (!call) {
        LOGGER_WARNING("Cannot handle error on 'null' call");
        return -1;
    }

    LOGGER_DEBUG("Sending error: %d on call: %s", errid, call->id);

    MSIMessage *msg_error = msi_new_message ( TypeResponse, error );

    msi_msg_set_reason ( msg_error, stringify_error(errid) );
    send_message ( session, call, msg_error, to );
    free ( msg_error );

    return 0;
}

/**
 * Determine 'bigger' call id
 */
static int call_id_bigger( const uint8_t *first, const uint8_t *second)
{
    return (memcmp(first, second, sizeof(MSICallIDType)) < 0);
}


/**
 * Set/change peer csettings
 */
static int flush_peer_csettings ( MSICall *call, MSIMessage *msg, int peer_id )
{
    if ( msg->csettings.exists ) {
        msi_msg_get_csettings(msg, &call->csettings_peer[peer_id]);

        LOGGER_DEBUG("Peer: %d \n"
                     "Type: %u \n"
                     "Video bitrate: %u \n"
                     "Video height: %u \n"
                     "Video width: %u \n"
                     "Audio bitrate: %u \n"
                     "Audio framedur: %u \n"
                     "Audio sample rate: %u \n"
                     "Audio channels: %u \n", peer_id,
                     call->csettings_peer[peer_id].call_type,
                     call->csettings_peer[peer_id].video_bitrate,
                     call->csettings_peer[peer_id].max_video_height,
                     call->csettings_peer[peer_id].max_video_width,
                     call->csettings_peer[peer_id].audio_bitrate,
                     call->csettings_peer[peer_id].audio_frame_duration,
                     call->csettings_peer[peer_id].audio_sample_rate,
                     call->csettings_peer[peer_id].audio_channels );

        return 0;
    }

    LOGGER_WARNING("No csettings header!");
    return -1;
}


/**
 * Add peer to peer list.
 */
static void add_peer( MSICall *call, int peer_id )
{
    uint32_t *peers = !call->peers ? peers = calloc(sizeof(uint32_t), 1) :
                      realloc( call->peers, sizeof(uint32_t) * call->peer_count);

    if (!peers) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        return;
    }

    call->peer_count ++;
    call->peers = peers;
    call->peers[call->peer_count - 1] = peer_id;

    LOGGER_DEBUG("Added peer: %d", peer_id);
}


static MSICall *find_call ( MSISession *session, uint8_t *call_id )
{
    if ( call_id == NULL ) return NULL;

    int32_t i = 0;

    for (; i < session->max_calls; i ++ )
        if ( session->calls[i] && memcmp(session->calls[i]->id, call_id, sizeof(session->calls[i]->id)) == 0 ) {
            return session->calls[i];
        }

    return NULL;
}

static MSICall *init_call ( MSISession *session, int peers, int ringing_timeout )
{

    if (peers == 0) {
        LOGGER_ERROR("No peers!");
        return NULL;
    }

    int32_t call_idx = 0;

    for (; call_idx < session->max_calls; call_idx ++) {
        if ( !session->calls[call_idx] ) {

            if (!(session->calls[call_idx] = calloc ( sizeof ( MSICall ), 1 ))) {
                LOGGER_WARNING("Allocation failed! Program might misbehave!");
                return NULL;
            }

            break;
        }
    }

    if ( call_idx == session->max_calls ) {
        LOGGER_WARNING("Reached maximum amount of calls!");
        return NULL;
    }


    MSICall *call = session->calls[call_idx];

    call->call_idx = call_idx;

    if ( !(call->csettings_peer = calloc ( sizeof ( MSICSettings ), peers )) ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        free(call);
        return NULL;
    }

    call->session = session;

    call->request_timer_id = 0;
    call->ringing_timer_id = 0;

    call->ringing_tout_ms = ringing_timeout;

    LOGGER_DEBUG("Started new call with index: %u", call_idx);
    return call;
}

static int terminate_call ( MSISession *session, MSICall *call )
{
    if ( !call ) {
        LOGGER_WARNING("Tried to terminate non-existing call!");
        return -1;
    }

    /* Check event loop and cancel timed events if there are any
     */
    timer_release ( session->timer_handler, call->request_timer_id);
    timer_release ( session->timer_handler, call->ringing_timer_id);

    session->calls[call->call_idx] = NULL;

    LOGGER_DEBUG("Terminated call id: %d", call->call_idx);

    free ( call->csettings_peer );
    free ( call->peers );
    free ( call );

    return 0;
}

static void handle_remote_connection_change(Messenger *messenger, uint32_t friend_num, uint8_t status, void *session_p)
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

/**
 * Function called at request timeout
 */
static void handle_timeout ( Timer *timer )
{
    /* TODO: Cancel might not arrive there; set up
     * timers on these cancels and terminate call on
     * their timeout
     */
    MSICall *call = timer->session->calls[timer->call_idx];


    if (call) {
        LOGGER_DEBUG("[Call: %d] Request timed out!", call->call_idx);

        invoke_callback(timer->session, timer->call_idx, msi_OnRequestTimeout);
        msi_cancel(timer->session, timer->call_idx, call->peers [0], "Request timed out");
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
            if (call->state == msi_CallInviting) {
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
                send_reponse(session, call, starting, msg->friend_id);
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
    call->state = msi_CallStarting;

    add_peer( call, msg->friend_id);
    flush_peer_csettings ( call, msg, 0 );
    send_reponse(session, call, ringing, msg->friend_id);
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

    send_reponse(session, call, ending, msg->friend_id);
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
    send_reponse(session, call, ending, msg->friend_id);
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

    } else if ( call->state == msi_CallInviting ) {
        LOGGER_DEBUG("Session: %p Handling 'starting' on call: %d", session, call->call_idx );

        call->state = msi_CallActive;

        MSIMessage *msg_start = msi_new_message ( TypeRequest, start );
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
static void msi_handle_packet ( Messenger *messenger, uint32_t source, const uint8_t *data, uint16_t length,
                                void *object )
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

    msg = parse_recv ( data, length );

    if ( !msg ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }

    msg->friend_id = source;

    pthread_mutex_lock(session->mutex);

    /* Find what call */
    MSICall *call = msg->callid.exists ? find_call(session, msg->callid.value ) : NULL;

    /* Now handle message */

    if ( msg->request.exists ) { /* Handle request */

        switch (msg->request.value) {
            case invite:
                handle_recv_invite ( session, call, msg );
                break;

            case start:
                handle_recv_start ( session, call, msg );
                break;

            case cancel:
                handle_recv_cancel ( session, call, msg );
                break;

            case reject:
                handle_recv_reject ( session, call, msg );
                break;

            case end:
                handle_recv_end ( session, call, msg );
                break;
        }

    } else if ( msg->response.exists ) { /* Handle response */

        /* Got response so cancel timer */
        if ( call ) timer_release(session->timer_handler, call->request_timer_id);

        switch (msg->response.value) {
            case ringing:
                handle_recv_ringing ( session, call, msg );
                break;

            case starting:
                handle_recv_starting ( session, call, msg );
                break;

            case ending:
                handle_recv_ending ( session, call, msg );
                break;

            case error:
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
void msi_register_callback ( MSISession *session, MSICallbackType callback, MSICallbackID id, void *userdata )
{
    session->callbacks[id].first = callback;
    session->callbacks[id].second = userdata;
}


MSISession *msi_new ( Messenger *messenger, int32_t max_calls )
{
    if (messenger == NULL) {
        LOGGER_ERROR("Could not init session on empty messenger!");
        return NULL;
    }

    if ( !max_calls ) {
        LOGGER_WARNING("Invalid max call treshold!");
        return NULL;
    }

    MSISession *retu = calloc ( sizeof ( MSISession ), 1 );

    if (retu == NULL) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if (!(retu->calls = calloc( sizeof (MSICall *), max_calls ))) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        goto error;
    }

    retu->timer_handler = calloc(1, sizeof(TimerHandler));

    if (retu->timer_handler == NULL) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        goto error;
    }

    /* Allocate space for timers */
    ((TimerHandler *)retu->timer_handler)->max_capacity = max_calls * 10;

    if (!(((TimerHandler *)retu->timer_handler)->timers = calloc(max_calls * 10, sizeof(Timer *)))) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        goto error;
    }

    if (create_recursive_mutex(retu->mutex) != 0) {
        LOGGER_ERROR("Failed to init mutex! Program might misbehave");
        goto error;
    }

    retu->messenger_handle = messenger;
    retu->agent_handler = NULL;
    retu->max_calls = max_calls;
    retu->frequ = 10000; /* default value? */
    retu->call_timeout = 30000; /* default value? */

    m_callback_msi_packet(messenger, msi_handle_packet, retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, retu);

    LOGGER_DEBUG("New msi session: %p max calls: %u", retu, max_calls);
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
            MSICallState state = session->calls[idx]->state;

            if (state == msi_CallInviting) {
                msi_cancel( session, idx, session->calls[idx]->peers [_it], "MSI session terminated!" );
            } else {
                msi_stopcall(session, idx);
            }
        }

    free(((TimerHandler *)session->timer_handler)->timers);
    free(session->timer_handler);

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

    MSIMessage *msg_invite = msi_new_message ( TypeRequest, invite );

    msi_msg_set_csettings(msg_invite, csettings);
    send_message ( session, call, msg_invite, friend_id );
    free( msg_invite );

    call->state = msi_CallInviting;

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

    MSIMessage *msg_end = msi_new_message ( TypeRequest, end );

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

    if ( session->calls[call_index]->state != msi_CallStarting ) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_starting = msi_new_message ( TypeResponse, starting );

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

    if ( session->calls[call_index]->state != msi_CallInviting ) {
        LOGGER_ERROR("Call is in invalid state: %u", session->calls[call_index]->state);
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_cancel = msi_new_message ( TypeRequest, cancel );

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

    if ( session->calls[call_index]->state != msi_CallStarting ) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return msi_ErrorInvalidState;
    }

    MSIMessage *msg_reject = msi_new_message ( TypeRequest, reject );

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

    MSIMessage *msg_invite = msi_new_message ( TypeRequest, invite );

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
