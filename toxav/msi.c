/**  toxmsi.c
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
 *
 *   Report bugs/suggestions at #tox-dev @ freenode.net:6667
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE

#include "msi.h"
#include "event.h"
#include "../toxcore/util.h"
#include "../toxcore/network.h"
#include "../toxcore/Messenger.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define same(x, y) strcmp((const char*) x, (const char*) y) == 0

#define MSI_MAXMSG_SIZE 1024

#define TYPE_REQUEST 1
#define TYPE_RESPONSE 2

unsigned char *VERSION_STRING = (unsigned char *)"0.3.1";
#define VERSION_STRLEN 5

#define CT_AUDIO_HEADER_VALUE "AUDIO"
#define CT_VIDEO_HEADER_VALUE "VIDEO"


/* Define default timeout for a request.
 * There is no behavior specified by the msi on what will
 * client do on timeout, but to call timeout callback.
 */
#define m_deftout 10000 /* in milliseconds */

/**
 * Protocol:
 *
 * | desc. ( 1 byte ) | length ( 2 bytes ) | value ( length bytes ) |
 *
 * ie.
 *
 * | 0x1 | 0x0 0x7 | "version"
 *
 * Means: it's field value with length of 7 bytes and value of "version"
 * It's similar to amp protocol
 */


#define GENERIC_HEADER(header) \
typedef struct _MSIHeader##header { \
uint8_t* header_value; \
uint16_t size; \
} MSIHeader##header;


GENERIC_HEADER ( Version )
GENERIC_HEADER ( Request )
GENERIC_HEADER ( Response )
GENERIC_HEADER ( CallType )
GENERIC_HEADER ( CallId )
GENERIC_HEADER ( Info )
GENERIC_HEADER ( Reason )
GENERIC_HEADER ( CryptoKey )
GENERIC_HEADER ( Nonce )


/**
 * @brief This is the message structure. It contains all of the headers and
 *        destination/source of the message stored in friend_id.
 *
 */
typedef struct _MSIMessage {

    MSIHeaderVersion   version;
    MSIHeaderRequest   request;
    MSIHeaderResponse  response;
    MSIHeaderCallType  calltype;
    MSIHeaderInfo      info;
    MSIHeaderReason    reason;
    MSIHeaderCallId    callid;
    MSIHeaderCryptoKey cryptokey;
    MSIHeaderNonce     nonce;

    struct _MSIMessage *next;

    int friend_id;

} MSIMessage;



static MSICallback callbacks[10] = {0};


/* define strings for the identifiers */
#define VERSION_FIELD      "Version"
#define REQUEST_FIELD      "Request"
#define RESPONSE_FIELD     "Response"
#define INFO_FIELD         "INFO"
#define REASON_FIELD       "Reason"
#define CALLTYPE_FIELD     "Call-type"
#define CALLID_FIELD       "Call-id"
#define CRYPTOKEY_FIELD    "Crypto-key"
#define NONCE_FIELD        "Nonce"

/* protocol descriptors */
#define end_byte    0x0
#define field_byte  0x1
#define value_byte  0x2


typedef enum {
    invite,
    start,
    cancel,
    reject,
    end,

} MSIRequest;


/**
 * @brief Get string value for request.
 *
 * @param request The request.
 * @return const uint8_t* The string
 */
static inline const uint8_t *stringify_request ( MSIRequest request )
{
    static const uint8_t *strings[] = {
        ( uint8_t * ) "INVITE",
        ( uint8_t * ) "START",
        ( uint8_t * ) "CANCEL",
        ( uint8_t * ) "REJECT",
        ( uint8_t * ) "END"
    };

    return strings[request];
}


typedef enum {
    ringing,
    starting,
    ending,
    error

} MSIResponse;


/**
 * @brief Get string value for response.
 *
 * @param response The response.
 * @return const uint8_t* The string
 */
static inline const uint8_t *stringify_response ( MSIResponse response )
{
    static const uint8_t *strings[] = {
        ( uint8_t * ) "ringing",
        ( uint8_t * ) "starting",
        ( uint8_t * ) "ending",
        ( uint8_t * ) "error"
    };

    return strings[response];
}


#define ON_HEADER(iterator, header, descriptor, size_const) \
( memcmp(iterator, descriptor, size_const) == 0){ /* Okay */ \
    iterator += size_const; /* Set iterator at begining of value part */ \
    if ( *iterator != value_byte ) { assert(0); return -1; }\
    iterator ++;\
    uint16_t _value_size = (uint16_t) *(iterator ) << 8 | \
    (uint16_t) *(iterator + 1); \
    header.header_value = calloc(sizeof(uint8_t), _value_size); \
    header.size = _value_size; \
    memcpy(header.header_value, iterator + 2, _value_size);\
    iterator = iterator + 2 + _value_size; /* set iterator at new header or end_byte */ \
}

/**
 * @brief Parse raw 'data' received from socket into MSIMessage struct.
 *        Every message has to have end value of 'end_byte' or _undefined_ behavior
 *        occures. The best practice is to check the end of the message at the handle_packet.
 *
 * @param msg Container.
 * @param data The data.
 * @return int
 * @retval -1 Error occured.
 * @retval 0 Success.
 */
int parse_raw_data ( MSIMessage *msg, const uint8_t *data, uint16_t length )
{
    assert ( msg );

    if ( data[length - 1] ) /* End byte must have value 0 */
        return -1;

    const uint8_t *_it = data;

    while ( *_it ) {/* until end_byte is hit */

        uint16_t itedlen = (_it - data) + 2;

        if ( *_it == field_byte && itedlen < length ) {

            uint16_t _size = ( uint16_t ) * ( _it + 1 ) << 8 |
                             ( uint16_t ) * ( _it + 2 );

            if ( itedlen + _size > length ) return -1;

            _it += 3; /* place it at the field value beginning */

            switch ( _size ) { /* Compare the size of the hardcoded values ( vary fast and convenient ) */

                case 4: { /* INFO header */
                    if ON_HEADER ( _it, msg->info, INFO_FIELD, 4 )
                    }
                break;

                case 5: { /* NONCE header */
                    if ON_HEADER ( _it, msg->nonce, NONCE_FIELD, 5 )
                    }
                break;

                case 6: { /* Reason header */
                    if ON_HEADER ( _it, msg->reason, REASON_FIELD, 6 )
                    }
                break;

                case 7: { /* Version, Request, Call-id headers */
                    if ON_HEADER ( _it, msg->version, VERSION_FIELD, 7 )
                        else if ON_HEADER ( _it, msg->request, REQUEST_FIELD, 7 )
                            else if ON_HEADER ( _it, msg->callid, CALLID_FIELD, 7 )
                            }
                break;

                case 8: { /* Response header */
                    if ON_HEADER ( _it, msg->response, RESPONSE_FIELD, 8 )
                    }
                break;

                case 9: { /* Call-type header */
                    if ON_HEADER ( _it, msg->calltype, CALLTYPE_FIELD, 9 )
                    }
                break;

                case 10: { /* Crypto-key headers */
                    if ON_HEADER ( _it, msg->cryptokey, CRYPTOKEY_FIELD, 10 )
                    }
                break;

                default:
                    return -1;
            }
        } else return -1;

        /* If it's anything else return failure as the message is invalid */

    }

    return 0;
}


#define ALLOCATE_HEADER( var, mheader_value, t_size) \
var.header_value = calloc(sizeof *mheader_value, t_size); \
memcpy(var.header_value, mheader_value, t_size); \
var.size = t_size;


/**
 * @brief Speaks for it self.
 *
 * @param msg The message.
 * @return void
 */
void free_message ( MSIMessage *msg )
{
    assert ( msg );

    free ( msg->calltype.header_value );
    free ( msg->request.header_value );
    free ( msg->response.header_value );
    free ( msg->version.header_value );
    free ( msg->info.header_value );
    free ( msg->cryptokey.header_value );
    free ( msg->nonce.header_value );
    free ( msg->reason.header_value );
    free ( msg->callid.header_value );

    free ( msg );
}


/**
 * @brief Create the message.
 *
 * @param type Request or response.
 * @param type_id Type of request/response.
 * @return MSIMessage* Created message.
 * @retval NULL Error occured.
 */
MSIMessage *msi_new_message ( uint8_t type, const uint8_t *type_id )
{
    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );
    assert ( _retu );

    if ( type == TYPE_REQUEST ) {
        ALLOCATE_HEADER ( _retu->request, type_id, strlen ( (const char *)type_id ) )

    } else if ( type == TYPE_RESPONSE ) {
        ALLOCATE_HEADER ( _retu->response, type_id, strlen ( (const char *)type_id ) )

    } else {
        free_message ( _retu );
        return NULL;
    }

    ALLOCATE_HEADER ( _retu->version, VERSION_STRING, strlen ( (const char *)VERSION_STRING ) )

    return _retu;
}


/**
 * @brief Parse data from handle_packet.
 *
 * @param data The data.
 * @return MSIMessage* Parsed message.
 * @retval NULL Error occured.
 */
MSIMessage *parse_message ( const uint8_t *data, uint16_t length )
{
    assert ( data );

    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );
    assert ( _retu );

    memset ( _retu, 0, sizeof ( MSIMessage ) );

    if ( parse_raw_data ( _retu, data, length ) == -1 ) {

        free_message ( _retu );
        return NULL;
    }

    if ( !_retu->version.header_value || VERSION_STRLEN != _retu->version.size ||
            memcmp ( _retu->version.header_value, VERSION_STRING, VERSION_STRLEN ) != 0 ) {

        free_message ( _retu );
        return NULL;
    }

    return _retu;
}



/**
 * @brief Speaks for it self.
 *
 * @param dest Container.
 * @param header_field Field.
 * @param header_value Field value.
 * @param value_len Length of field value.
 * @param length Pointer to container length.
 * @return uint8_t* Iterated container.
 */
uint8_t *append_header_to_string (
    uint8_t *dest,
    const uint8_t *header_field,
    const uint8_t *header_value,
    uint16_t value_len,
    uint16_t *length )
{
    assert ( dest );
    assert ( header_value );
    assert ( header_field );

    const uint8_t *_hvit = header_value;
    uint16_t _total = 6 + value_len; /* 6 is known plus header value len + field len*/

    *dest = field_byte; /* Set the first byte */

    uint8_t *_getback_byte = dest + 1; /* remeber the byte we were on */
    dest += 3; /* swith to 4th byte where field value starts */

    /* Now set the field value and calculate it's length */
    uint16_t _i = 0;

    for ( ; header_field[_i]; ++_i ) {
        *dest = header_field[_i];
        ++dest;
    };

    _total += _i;

    /* Now set the length of the field byte */
    *_getback_byte = ( uint8_t ) _i >> 8;

    _getback_byte++;

    *_getback_byte = ( uint8_t ) _i;

    /* for value part do it regulary */
    *dest = value_byte;

    dest++;

    *dest = ( uint8_t ) value_len >> 8;

    dest++;

    *dest = ( uint8_t ) value_len;

    dest++;

    for ( _i = value_len; _i; --_i ) {
        *dest = *_hvit;
        ++_hvit;
        ++dest;
    }

    *length += _total;
    return dest;
}


#define CLEAN_ASSIGN(added, var, field, header)\
if ( header.header_value ) { var = append_header_to_string(var, (const uint8_t*)field, header.header_value, header.size, &added); }


/**
 * @brief Convert MSIMessage struct to _sendable_ string.
 *
 * @param msg The message.
 * @param dest Destination.
 * @return uint16_t It's final size.
 */
uint16_t message_to_string ( MSIMessage *msg, uint8_t *dest )
{
    assert ( msg );
    assert ( dest );

    uint8_t *_iterated = dest;
    uint16_t _size = 0;

    CLEAN_ASSIGN ( _size, _iterated, VERSION_FIELD, msg->version );
    CLEAN_ASSIGN ( _size, _iterated, REQUEST_FIELD, msg->request );
    CLEAN_ASSIGN ( _size, _iterated, RESPONSE_FIELD, msg->response );
    CLEAN_ASSIGN ( _size, _iterated, CALLTYPE_FIELD, msg->calltype );
    CLEAN_ASSIGN ( _size, _iterated, INFO_FIELD, msg->info );
    CLEAN_ASSIGN ( _size, _iterated, CALLID_FIELD, msg->callid );
    CLEAN_ASSIGN ( _size, _iterated, REASON_FIELD, msg->reason );
    CLEAN_ASSIGN ( _size, _iterated, CRYPTOKEY_FIELD, msg->cryptokey );
    CLEAN_ASSIGN ( _size, _iterated, NONCE_FIELD, msg->nonce );

    *_iterated = end_byte;
    _size ++;

    return _size;
}


#define GENERIC_SETTER_DEFINITION(header) \
void msi_msg_set_##header ( MSIMessage* _msg, const uint8_t* header_value, uint16_t _size ) \
{ assert(_msg); assert(header_value); \
  free(_msg->header.header_value); \
  ALLOCATE_HEADER( _msg->header, header_value, _size )}

GENERIC_SETTER_DEFINITION ( calltype )
GENERIC_SETTER_DEFINITION ( reason )
GENERIC_SETTER_DEFINITION ( info )
GENERIC_SETTER_DEFINITION ( callid )
GENERIC_SETTER_DEFINITION ( cryptokey )
GENERIC_SETTER_DEFINITION ( nonce )


/**
 * @brief Generate _random_ alphanumerical string.
 *
 * @param str Destination.
 * @param size Size of string.
 * @return void
 */
void t_randomstr ( uint8_t *str, size_t size )
{
    assert ( str );

    static const uint8_t _bytes[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    size_t _it = 0;

    for ( ; _it < size; _it++ ) {
        str[_it] = _bytes[ random_int() % 61 ];
    }
}


typedef enum {
    error_deadcall = 1,  /* has call id but it's from old call */
    error_id_mismatch,   /* non-existing call */

    error_no_callid,     /* not having call id */
    error_no_call,       /* no call in session */
    error_no_crypto_key, /* no crypto key */

    error_busy

} MSICallError;          /* Error codes */


/**
 * @brief Stringify error code.
 *
 * @param error_code The code.
 * @return const uint8_t* The string.
 */
static inline const uint8_t *stringify_error ( MSICallError error_code )
{
    static const uint8_t *strings[] = {
        ( uint8_t * ) "",
        ( uint8_t * ) "Using dead call",
        ( uint8_t * ) "Call id not set to any call",
        ( uint8_t * ) "Call id not available",
        ( uint8_t * ) "No active call in session",
        ( uint8_t * ) "No Crypto-key set",
        ( uint8_t * ) "Callee busy"
    };

    return strings[error_code];
}


/**
 * @brief Convert error_code into string.
 *
 * @param error_code The code.
 * @return const uint8_t* The string.
 */
static inline const uint8_t *stringify_error_code ( MSICallError error_code )
{
    static const uint8_t *strings[] = {
        ( uint8_t * ) "",
        ( uint8_t * ) "1",
        ( uint8_t * ) "2",
        ( uint8_t * ) "3",
        ( uint8_t * ) "4",
        ( uint8_t * ) "5",
        ( uint8_t * ) "6"
    };

    return strings[error_code];
}


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param msg The message.
 * @param to Where to.
 * @return int
 * @retval -1 Error occured.
 * @retval 0 Success.
 */
int send_message ( MSISession *session, MSIMessage *msg, uint32_t to )
{
    msi_msg_set_callid ( msg, session->call->id, CALL_ID_LEN );

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];
    uint16_t _length = message_to_string ( msg, _msg_string_final );

    return m_msi_packet(session->messenger_handle, to, _msg_string_final, _length) ? 0 : -1;
}


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param msg The message.
 * @param peer_id The peer.
 * @return void
 */
void flush_peer_type ( MSISession *session, MSIMessage *msg, int peer_id )
{
    if ( msg->calltype.header_value ) {
        if ( strcmp ( ( const char * ) msg->calltype.header_value, CT_AUDIO_HEADER_VALUE ) == 0 ) {
            session->call->type_peer[peer_id] = type_audio;

        } else if ( strcmp ( ( const char * ) msg->calltype.header_value, CT_VIDEO_HEADER_VALUE ) == 0 ) {
            session->call->type_peer[peer_id] = type_video;
        } else {} /* Error */
    } else {} /* Error */
}

void handle_remote_connection_change(Messenger *messenger, int friend_num, uint8_t status, void *session_p)
{
    MSISession *session = session_p;

    switch ( status ) {
        case 0: { /* Went offline */
            if ( session->call ) {
                int i = 0;

                for ( ; i < session->call->peer_count; i ++ )
                    if ( session->call->peers[i] == friend_num ) {
                        msi_stopcall(session); /* Stop the call for now */
                        return;
                    }
            }
        }
        break;

        default:
            break;
    }
}

/**
 * @brief Sends error response to peer.
 *
 * @param session The session.
 * @param errid The id.
 * @param to Where to?
 * @return int
 * @retval 0 It's always success.
 */
int handle_error ( MSISession *session, MSICallError errid, uint32_t to )
{
    MSIMessage *_msg_error = msi_new_message ( TYPE_RESPONSE, stringify_response ( error ) );

    const uint8_t *_error_code_str = stringify_error_code ( errid );

    msi_msg_set_reason ( _msg_error, _error_code_str, strlen ( ( const char * ) _error_code_str ) );
    send_message ( session, _msg_error, to );
    free_message ( _msg_error );

    session->last_error_id = errid;
    session->last_error_str = stringify_error ( errid );

    event.rise ( callbacks[MSI_OnError], session->agent_handler );

    return 0;
}


/**
 * @brief Determine the error if any.
 *
 * @param session Control session.
 * @param msg The message.
 * @return int
 * @retval -1 No error.
 * @retval 0 Error occured and response sent.
 */
int has_call_error ( MSISession *session, MSIMessage *msg )
{
    if ( !msg->callid.header_value ) {
        return handle_error ( session, error_no_callid, msg->friend_id );

    } else if ( !session->call ) {
        return handle_error ( session, error_no_call, msg->friend_id );

    } else if ( memcmp ( session->call->id, msg->callid.header_value, CALL_ID_LEN ) != 0 ) {
        return handle_error ( session, error_id_mismatch, msg->friend_id );

    }

    return -1;
}


/**
 * @brief Function called at request timeout.
 *
 * @param arg Control session
 * @return void*
 */
void *handle_timeout ( void *arg )
{
    /* Send hangup either way */
    MSISession *_session = arg;

    if ( _session && _session->call ) {

        uint32_t *_peers = _session->call->peers;
        uint16_t  _peer_count = _session->call->peer_count;


        /* Cancel all? */
        uint16_t _it = 0;

        for ( ; _it < _peer_count; _it++ )
            msi_cancel ( arg, _peers[_it], (const uint8_t *)"Timeout" );

    }

    ( *callbacks[MSI_OnRequestTimeout] ) ( _session->agent_handler );
    ( *callbacks[MSI_OnEnding ] )        ( _session->agent_handler );

    return NULL;
}


/**
 * @brief Add peer to peer list.
 *
 * @param call What call.
 * @param peer_id Its id.
 * @return void
 */
void add_peer( MSICall *call, int peer_id )
{
    if ( !call->peers ) {
        call->peers = calloc(sizeof(int), 1);
        call->peer_count = 1;
    } else {
        call->peer_count ++;
        call->peers = realloc( call->peers, sizeof(int) * call->peer_count);
    }

    call->peers[call->peer_count - 1] = peer_id;
}


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param peers Amount of peers. (Currently it only supports 1)
 * @param ringing_timeout Ringing timeout.
 * @return MSICall* The created call.
 */
MSICall *init_call ( MSISession *session, int peers, int ringing_timeout )
{
    assert ( session );
    assert ( peers );

    MSICall *_call = calloc ( sizeof ( MSICall ), 1 );
    _call->type_peer = calloc ( sizeof ( MSICallType ), peers );

    assert ( _call );
    assert ( _call->type_peer );

    /*_call->_participant_count = _peers;*/

    _call->request_timer_id = 0;
    _call->ringing_timer_id = 0;

    _call->key_local = NULL;
    _call->key_peer = NULL;
    _call->nonce_local = NULL;
    _call->nonce_peer = NULL;

    _call->ringing_tout_ms = ringing_timeout;

    pthread_mutex_init ( &_call->mutex, NULL );

    return _call;
}


/**
 * @brief Terminate the call.
 *
 * @param session Control session.
 * @return int
 * @retval -1 Error occured.
 * @retval 0 Success.
 */
int terminate_call ( MSISession *session )
{
    assert ( session );

    if ( !session->call )
        return -1;


    /* Check event loop and cancel timed events if there are any
     * NOTE: This has to be done before possibly
     * locking the mutex the second time
     */
    event.timer_release ( session->call->request_timer_id );
    event.timer_release ( session->call->ringing_timer_id );

    /* Get a handle */
    pthread_mutex_lock ( &session->call->mutex );

    MSICall *_call = session->call;
    session->call = NULL;

    free ( _call->type_peer );
    free ( _call->key_local );
    free ( _call->key_peer );
    free ( _call->peers);

    /* Release handle */
    pthread_mutex_unlock ( &_call->mutex );

    pthread_mutex_destroy ( &_call->mutex );

    free ( _call );

    return 0;
}


/********** Request handlers **********/
int handle_recv_invite ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( session->call ) {
        handle_error ( session, error_busy, msg->friend_id );
        return 0;
    }

    if ( !msg->callid.header_value ) {
        handle_error ( session, error_no_callid, msg->friend_id );
        return 0;
    }

    session->call = init_call ( session, 1, 0 );
    memcpy ( session->call->id, msg->callid.header_value, CALL_ID_LEN );
    session->call->state = call_starting;

    add_peer( session->call, msg->friend_id);

    flush_peer_type ( session, msg, 0 );

    MSIMessage *_msg_ringing = msi_new_message ( TYPE_RESPONSE, stringify_response ( ringing ) );
    send_message ( session, _msg_ringing, msg->friend_id );
    free_message ( _msg_ringing );

    event.rise ( callbacks[MSI_OnInvite], session->agent_handler );

    return 1;
}
int handle_recv_start ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;

    if ( !msg->cryptokey.header_value )
        return handle_error ( session, error_no_crypto_key, msg->friend_id );

    session->call->state = call_active;

    session->call->key_peer = calloc ( sizeof ( uint8_t ), crypto_secretbox_KEYBYTES );
    memcpy ( session->call->key_peer, msg->cryptokey.header_value, crypto_secretbox_KEYBYTES );

    session->call->nonce_peer = calloc ( sizeof ( uint8_t ), crypto_secretbox_NONCEBYTES );
    memcpy ( session->call->nonce_peer, msg->nonce.header_value,  crypto_secretbox_NONCEBYTES );

    flush_peer_type ( session, msg, 0 );

    event.rise ( callbacks[MSI_OnStart], session->agent_handler );

    return 1;
}
int handle_recv_reject ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;


    MSIMessage *_msg_end = msi_new_message ( TYPE_REQUEST, stringify_request ( end ) );
    send_message ( session, _msg_end, msg->friend_id );
    free_message ( _msg_end );

    event.timer_release ( session->call->request_timer_id );
    event.rise ( callbacks[MSI_OnReject], session->agent_handler );
    session->call->request_timer_id = event.timer_alloc ( handle_timeout, session, m_deftout );

    return 1;
}
int handle_recv_cancel ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;


    terminate_call ( session );

    event.rise ( callbacks[MSI_OnCancel], session->agent_handler );

    return 1;
}
int handle_recv_end ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;


    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );

    terminate_call ( session );

    event.rise ( callbacks[MSI_OnEnd], session->agent_handler );

    return 1;
}

/********** Response handlers **********/
int handle_recv_ringing ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;

    session->call->ringing_timer_id = event.timer_alloc ( handle_timeout, session, session->call->ringing_tout_ms );
    event.rise ( callbacks[MSI_OnRinging], session->agent_handler );

    return 1;
}
int handle_recv_starting ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;

    if ( !msg->cryptokey.header_value ) {
        return handle_error ( session, error_no_crypto_key, msg->friend_id );
    }

    /* Generate local key/nonce to send */
    session->call->key_local = calloc ( sizeof ( uint8_t ), crypto_secretbox_KEYBYTES );
    new_symmetric_key ( session->call->key_local );

    session->call->nonce_local = calloc ( sizeof ( uint8_t ), crypto_secretbox_NONCEBYTES );
    new_nonce ( session->call->nonce_local );

    /* Save peer key/nonce */
    session->call->key_peer = calloc ( sizeof ( uint8_t ), crypto_secretbox_KEYBYTES );
    memcpy ( session->call->key_peer, msg->cryptokey.header_value, crypto_secretbox_KEYBYTES );

    session->call->nonce_peer = calloc ( sizeof ( uint8_t ), crypto_secretbox_NONCEBYTES );
    memcpy ( session->call->nonce_peer, msg->nonce.header_value,  crypto_secretbox_NONCEBYTES );

    session->call->state = call_active;

    MSIMessage *_msg_start = msi_new_message ( TYPE_REQUEST, stringify_request ( start ) );
    msi_msg_set_cryptokey ( _msg_start, session->call->key_local, crypto_secretbox_KEYBYTES );
    msi_msg_set_nonce ( _msg_start, session->call->nonce_local, crypto_secretbox_NONCEBYTES );
    send_message ( session, _msg_start, msg->friend_id );
    free_message ( _msg_start );

    flush_peer_type ( session, msg, 0 );

    event.rise ( callbacks[MSI_OnStarting], session->agent_handler );
    event.timer_release ( session->call->ringing_timer_id );

    return 1;
}
int handle_recv_ending ( MSISession *session, MSIMessage *msg )
{
    assert ( session );

    if ( has_call_error ( session, msg ) == 0 )
        return 0;


    terminate_call ( session );

    event.rise ( callbacks[MSI_OnEnding], session->agent_handler );

    return 1;
}
int handle_recv_error ( MSISession *session, MSIMessage *msg )
{
    assert ( session );
    assert ( session->call );

    /* Handle error accordingly */
    if ( msg->reason.header_value ) {
        session->last_error_id = atoi ( ( const char * ) msg->reason.header_value );
        session->last_error_str = stringify_error ( session->last_error_id );
    }

    terminate_call ( session );

    event.rise ( callbacks[MSI_OnEnding], session->agent_handler );

    return 1;
}


/**
 * @brief BASIC call flow:
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
void msi_handle_packet ( Messenger *messenger, int source, uint8_t *data, uint16_t length, void *object )
{
    /* Unused */
    (void)messenger;

    MSISession *_session = object;
    MSIMessage *_msg;

    if ( !length ) return;

    _msg = parse_message ( data, length );

    if ( !_msg ) return;

    _msg->friend_id = source;


    /* Now handle message */

    if ( _msg->request.header_value ) { /* Handle request */

        const uint8_t *_request_value = _msg->request.header_value;

        if ( same ( _request_value, stringify_request ( invite ) ) ) {
            handle_recv_invite ( _session, _msg );

        } else if ( same ( _request_value, stringify_request ( start ) ) ) {
            handle_recv_start ( _session, _msg );

        } else if ( same ( _request_value, stringify_request ( cancel ) ) ) {
            handle_recv_cancel ( _session, _msg );

        } else if ( same ( _request_value, stringify_request ( reject ) ) ) {
            handle_recv_reject ( _session, _msg );

        } else if ( same ( _request_value, stringify_request ( end ) ) ) {
            handle_recv_end ( _session, _msg );
        }

        else {
            free_message ( _msg );
            return;
        }

    } else if ( _msg->response.header_value ) { /* Handle response */

        const uint8_t *_response_value = _msg->response.header_value;

        if ( same ( _response_value, stringify_response ( ringing ) ) ) {
            handle_recv_ringing ( _session, _msg );

        } else if ( same ( _response_value, stringify_response ( starting ) ) ) {
            handle_recv_starting ( _session, _msg );

        } else if ( same ( _response_value, stringify_response ( ending ) ) ) {
            handle_recv_ending ( _session, _msg );

        } else if ( same ( _response_value, stringify_response ( error ) ) ) {
            handle_recv_error ( _session, _msg );
        } else {
            free_message ( _msg );
            return;
        }

        /* Got response so cancel timer */
        if ( _session->call )
            event.timer_release ( _session->call->request_timer_id );

    }

    free_message ( _msg );
}


/********************************************************************************************************************
 * *******************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 *
 *
 *
 * PUBLIC API FUNCTIONS IMPLEMENTATIONS
 *
 *
 *
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************/








/**
 * @brief Callback setter.
 *
 * @param callback The callback.
 * @param id The id.
 * @return void
 */
void msi_register_callback ( MSICallback callback, MSICallbackID id )
{
    callbacks[id] = callback;
}


/**
 * @brief Start the control session.
 *
 * @param messenger Tox* object.
 * @param user_agent User agent, i.e. 'Venom'; 'QT-gui'
 * @return MSISession* The created session.
 * @retval NULL Error occured.
 */
MSISession *msi_init_session ( Messenger* messenger )
{
    assert ( messenger );

    MSISession *_retu = calloc ( sizeof ( MSISession ), 1 );
    assert ( _retu );

    _retu->messenger_handle = messenger;
    _retu->agent_handler = NULL;

    _retu->call = NULL;

    _retu->frequ = 10000; /* default value? */
    _retu->call_timeout = 30000; /* default value? */


    m_callback_msi_packet(messenger, msi_handle_packet, _retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, _retu);

    return _retu;
}


/**
 * @brief Terminate control session.
 *
 * @param session The session
 * @return int
 */
int msi_terminate_session ( MSISession *session )
{
    assert ( session );

    int _status = 0;

    terminate_call ( session );
    m_callback_msi_packet((struct Messenger *) session->messenger_handle, NULL, NULL);


    /* TODO: Clean it up more? */

    free ( session );
    return _status;
}


/**
 * @brief Send invite request to friend_id.
 *
 * @param session Control session.
 * @param call_type Type of the call. Audio or Video(both audio and video)
 * @param rngsec Ringing timeout.
 * @param friend_id The friend.
 * @return int
 */
int msi_invite ( MSISession *session, MSICallType call_type, uint32_t rngsec, uint32_t friend_id )
{
    assert ( session );

    MSIMessage *_msg_invite = msi_new_message ( TYPE_REQUEST, stringify_request ( invite ) );

    session->call = init_call ( session, 1, rngsec ); /* Just one for now */
    t_randomstr ( session->call->id, CALL_ID_LEN );

    add_peer(session->call, friend_id );

    session->call->type_local = call_type;
    /* Do whatever with message */

    if ( call_type == type_audio ) {
        msi_msg_set_calltype
        ( _msg_invite, ( const uint8_t * ) CT_AUDIO_HEADER_VALUE, strlen ( CT_AUDIO_HEADER_VALUE ) );
    } else {
        msi_msg_set_calltype
        ( _msg_invite, ( const uint8_t * ) CT_VIDEO_HEADER_VALUE, strlen ( CT_VIDEO_HEADER_VALUE ) );
    }

    send_message ( session, _msg_invite, friend_id );
    free_message ( _msg_invite );

    session->call->state = call_inviting;

    session->call->request_timer_id = event.timer_alloc ( handle_timeout, session, m_deftout );

    return 0;
}


/**
 * @brief Hangup active call.
 *
 * @param session Control session.
 * @return int
 * @retval -1 Error occured.
 * @retval 0 Success.
 */
int msi_hangup ( MSISession *session )
{
    assert ( session );

    if ( !session->call || session->call->state != call_active )
        return -1;

    MSIMessage *_msg_ending = msi_new_message ( TYPE_REQUEST, stringify_request ( end ) );

    /* hangup for each peer */
    int _it = 0;

    for ( ; _it < session->call->peer_count; _it ++ )
        send_message ( session, _msg_ending, session->call->peers[_it] );


    free_message ( _msg_ending );

    session->call->request_timer_id = event.timer_alloc ( handle_timeout, session, m_deftout );

    return 0;
}


/**
 * @brief Answer active call request.
 *
 * @param session Control session.
 * @param call_type Answer with Audio or Video(both).
 * @return int
 */
int msi_answer ( MSISession *session, MSICallType call_type )
{
    assert ( session );

    MSIMessage *_msg_starting = msi_new_message ( TYPE_RESPONSE, stringify_response ( starting ) );
    session->call->type_local = call_type;

    if ( call_type == type_audio ) {
        msi_msg_set_calltype
        ( _msg_starting, ( const uint8_t * ) CT_AUDIO_HEADER_VALUE, strlen ( CT_AUDIO_HEADER_VALUE ) );
    } else {
        msi_msg_set_calltype
        ( _msg_starting, ( const uint8_t * ) CT_VIDEO_HEADER_VALUE, strlen ( CT_VIDEO_HEADER_VALUE ) );
    }

    /* Now set the local encryption key and pass it with STARTING message */

    session->call->key_local = calloc ( sizeof ( uint8_t ), crypto_secretbox_KEYBYTES );
    new_symmetric_key ( session->call->key_local );

    session->call->nonce_local = calloc ( sizeof ( uint8_t ), crypto_secretbox_NONCEBYTES );
    new_nonce ( session->call->nonce_local );

    msi_msg_set_cryptokey ( _msg_starting, session->call->key_local, crypto_secretbox_KEYBYTES );
    msi_msg_set_nonce ( _msg_starting, session->call->nonce_local, crypto_secretbox_NONCEBYTES );

    send_message ( session, _msg_starting, session->call->peers[session->call->peer_count - 1] );
    free_message ( _msg_starting );

    session->call->state = call_active;

    return 0;
}


/**
 * @brief Cancel request.
 *
 * @param session Control session.
 * @param reason Set optional reason header. Pass NULL if none.
 * @return int
 */
int msi_cancel ( MSISession *session, uint32_t peer, const uint8_t *reason )
{
    assert ( session );

    MSIMessage *_msg_cancel = msi_new_message ( TYPE_REQUEST, stringify_request ( cancel ) );

    if ( reason ) msi_msg_set_reason(_msg_cancel, reason, strlen((const char *)reason));

    send_message ( session, _msg_cancel, peer );
    free_message ( _msg_cancel );

    terminate_call ( session );

    return 0;
}


/**
 * @brief Reject request.
 *
 * @param session Control session.
 * @return int
 */
int msi_reject ( MSISession *session, const uint8_t *reason )
{
    assert ( session );

    MSIMessage *_msg_reject = msi_new_message ( TYPE_REQUEST, stringify_request ( reject ) );

    if ( reason ) msi_msg_set_reason(_msg_reject, reason, strlen((const char *)reason) + 1);

    send_message ( session, _msg_reject, session->call->peers[session->call->peer_count - 1] );
    free_message ( _msg_reject );

    session->call->request_timer_id = event.timer_alloc ( handle_timeout, session, m_deftout );

    return 0;
}


/**
 * @brief Terminate the current call.
 *
 * @param session Control session.
 * @return int
 */
int msi_stopcall ( MSISession *session )
{
    assert ( session );

    if ( !session->call )
        return -1;

    /* just terminate it */

    terminate_call ( session );

    return 0;
}