/**  toxmsi.c
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is open source software: you can redistribute it and/or modify
 *   it under the terms of the StopNerds Public License as published by
 *   the StopNerds Foundation, either version 1 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   StopNerds Public License for more details.
 *
 *   You should have received a copy of the StopNerds Public License
 *   along with Tox. If not, see <http://stopnerds.org/license/>.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include "msi.h"
#include "event.h"


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


static struct _Callbacks {
    MSICallback function;
    void *data;
} callbacks[11] = {0};

inline__ void invoke_callback(int32_t call_index, MSICallbackID id)
{
    /*if ( callbacks[id].function ) event.rise ( callbacks[id].function, callbacks[id].data );*/
    if ( callbacks[id].function ) {
        LOGGER_DEBUG("Invoking callback function: %d", id);
        callbacks[id].function ( call_index, callbacks[id].data );
    }
}

/*static MSICallback callbacks[10] = {0};*/


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
static inline__ const uint8_t *stringify_request ( MSIRequest request )
{
    static const uint8_t *strings[] = {
        ( uint8_t *) "INVITE",
        ( uint8_t *) "START",
        ( uint8_t *) "CANCEL",
        ( uint8_t *) "REJECT",
        ( uint8_t *) "END"
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
static inline__ const uint8_t *stringify_response ( MSIResponse response )
{
    static const uint8_t *strings[] = {
        ( uint8_t *) "ringing",
        ( uint8_t *) "starting",
        ( uint8_t *) "ending",
        ( uint8_t *) "error"
    };

    return strings[response];
}



/**
 * @brief Parse raw 'data' received from socket into MSIMessage struct.
 *        Every message has to have end value of 'end_byte' or _undefined_ behavior
 *        occures. The best practice is to check the end of the message at the handle_packet.
 *
 * @param msg Container.
 * @param data The data.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int parse_raw_data ( MSIMessage *msg, const uint8_t *data, uint16_t length )
{

#define ON_HEADER(iterator, size_con, header, descriptor, type_size_const) \
( memcmp(iterator, descriptor, type_size_const) == 0){ /* Okay */ \
iterator += type_size_const; /* Set iterator at begining of value part */ \
if ( *iterator != value_byte || size_con <= type_size_const) { return -1; } size_con -= type_size_const; \
iterator ++; if(size_con <= 3) {return -1;} size_con -= 3; \
uint16_t _value_size; memcpy(&_value_size, iterator, sizeof(_value_size)); _value_size = ntohs(_value_size);\
if(size_con < _value_size) { return -1; } size_con -= _value_size; \
header.header_value = calloc(sizeof(uint8_t), _value_size); \
header.size = _value_size; \
memcpy(header.header_value, iterator + 2, _value_size);\
iterator = iterator + 2 + _value_size; /* set iterator at new header or end_byte */ }

    if ( msg == NULL ) {
        LOGGER_ERROR("Could not parse message: no storage!");
        return -1;
    }

    if ( data[length - 1] ) /* End byte must have value 0 */
        return -1;

    const uint8_t *_it = data;
    uint16_t size_max = length;

    while ( *_it ) {/* until end_byte is hit */

        uint16_t itedlen = (_it - data) + 2;

        if ( *_it == field_byte && itedlen < length ) {

            uint16_t _size;
            memcpy(&_size, _it + 1, sizeof(_size));
            _size = ntohs(_size);

            if ( itedlen + _size > length ) return -1;

            _it += 3; /* place it at the field value beginning */
            size_max -= 3;

            switch ( _size ) { /* Compare the size of the hardcoded values ( vary fast and convenient ) */

                case 4: { /* INFO header */
                    if ON_HEADER ( _it, size_max, msg->info, INFO_FIELD, 4 )
                    }
                break;

                case 5: { /* NONCE header */
                    if ON_HEADER ( _it, size_max, msg->nonce, NONCE_FIELD, 5 )
                    }
                break;

                case 6: { /* Reason header */
                    if ON_HEADER ( _it, size_max, msg->reason, REASON_FIELD, 6 )
                    }
                break;

                case 7: { /* Version, Request, Call-id headers */
                    if ON_HEADER ( _it, size_max, msg->version, VERSION_FIELD, 7 )
                        else if ON_HEADER ( _it, size_max, msg->request, REQUEST_FIELD, 7 )
                            else if ON_HEADER ( _it, size_max, msg->callid, CALLID_FIELD, 7 )
                            }
                break;

                case 8: { /* Response header */
                    if ON_HEADER ( _it, size_max, msg->response, RESPONSE_FIELD, 8 )
                    }
                break;

                case 9: { /* Call-type header */
                    if ON_HEADER ( _it, size_max, msg->calltype, CALLTYPE_FIELD, 9 )
                    }
                break;

                case 10: { /* Crypto-key headers */
                    if ON_HEADER ( _it, size_max, msg->cryptokey, CRYPTOKEY_FIELD, 10 )
                    }
                break;

                default:
                    LOGGER_ERROR("Unkown field value");
                    return -1;
            }
        } else {
            LOGGER_ERROR("Invalid field byte or field size too large");
            return -1;
        }

        /* If it's anything else return failure as the message is invalid */

    }

    return 0;
}


#define ALLOCATE_HEADER( var, mheader_value, t_size) \
var.header_value = calloc(sizeof *mheader_value, t_size); \
if (var.header_value == NULL) { LOGGER_WARNING("Header allocation failed!"); } \
else { memcpy(var.header_value, mheader_value, t_size); \
var.size = t_size; }


/**
 * @brief Speaks for it self.
 *
 * @param msg The message.
 * @return void
 */
void free_message ( MSIMessage *msg )
{
    if ( msg == NULL ) {
        LOGGER_WARNING("Tried to free empty message");
        return;
    }

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
 * @retval NULL Error occurred.
 */
MSIMessage *msi_new_message ( uint8_t type, const uint8_t *type_id )
{
    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( _retu == NULL ) {
        LOGGER_WARNING("Allocation failed!");
        return NULL;
    }

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
 * @retval NULL Error occurred.
 */
MSIMessage *parse_message ( const uint8_t *data, uint16_t length )
{
    if ( data == NULL ) {
        LOGGER_WARNING("Tried to parse empty message!");
        return NULL;
    }

    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( _retu == NULL ) {
        LOGGER_WARNING("Allocation failed!");
        return NULL;
    }

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
 * @brief Makes clear message presentation
 *
 * @param msg Message
 * @param dest Dest string
 * @return int
 */
int stringify_message(MSIMessage *msg, char *dest)
{
// THIS CODE HAS NO EFFECT, AND THE ARGUMENTS ARE NOT MODIFIED
#if 0

#define HDR_TO_STR(__dest, __hdr) if (__hdr.header_value) {\
    char nltstr[MSI_MAXMSG_SIZE]; memset(nltstr+__hdr.size, '\0', MSI_MAXMSG_SIZE-__hdr.size); int i = 0; \
    for ( ; i < __hdr.size; i ++) nltstr[i] = (char)__hdr.header_value[i]; \
    }

    if ( !msg || !dest )
        return -1;

    HDR_TO_STR(dest, msg->version);
    HDR_TO_STR(dest, msg->request);
    HDR_TO_STR(dest, msg->response);
    HDR_TO_STR(dest, msg->reason);
    HDR_TO_STR(dest, msg->callid);
    HDR_TO_STR(dest, msg->calltype);
    HDR_TO_STR(dest, msg->cryptokey);
    HDR_TO_STR(dest, msg->nonce);

//     if (msg->version.header_value) {
//         U8_TO_NLTCHAR(msg->version.header_value, msg->version.size, nltstr, MSI_MAXMSG_SIZE);
//         sprintf(dest, "Version: %s\n", nltstr);
//     }
#endif

    return 0;
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
    if ( dest == NULL ) {
        LOGGER_ERROR("No destination space!");
        assert(dest);
    }

    if (header_value == NULL) {
        LOGGER_ERROR("Empty header value");
        return NULL;
    }

    if ( header_field == NULL ) {
        LOGGER_ERROR("Empty header field");
        return NULL;
    }


    const uint8_t *_hvit = header_value;
    uint16_t _total = 6 + value_len; /* 6 is known plus header value len + field len*/

    *dest = field_byte; /* Set the first byte */

    uint8_t *_getback_byte = dest + 1; /* remember the byte we were on */
    dest += 3; /* swith to 4th byte where field value starts */

    /* Now set the field value and calculate it's length */
    uint16_t _i = 0;

    for ( ; header_field[_i]; ++_i ) {
        *dest = header_field[_i];
        ++dest;
    };

    _total += _i;

    /* Now set the length of the field byte */
    uint16_t _convert;


    _convert = htons(_i);

    memcpy(_getback_byte, &_convert, sizeof(_convert));

    /* for value part do it regulary */
    *dest = value_byte;

    dest++;


    _convert = htons(value_len);

    memcpy(dest, &_convert, sizeof(_convert));

    dest += 2;

    for ( _i = value_len; _i; --_i ) {
        *dest = *_hvit;
        ++_hvit;
        ++dest;
    }

    *length += _total;
    return dest;
}


/**
 * @brief Convert MSIMessage struct to _sendable_ string.
 *
 * @param msg The message.
 * @param dest Destination.
 * @return uint16_t It's final size.
 */
uint16_t message_to_send ( MSIMessage *msg, uint8_t *dest )
{
#define CLEAN_ASSIGN(added, var, field, header)\
    if ( header.header_value ) { var = append_header_to_string(var, (const uint8_t*)field, header.header_value, header.size, &added); }

    if (msg == NULL) {
        LOGGER_ERROR("Empty message!");
        return 0;
    }

    if (dest == NULL ) {
        LOGGER_ERROR("Empty destination!");
        return 0;
    }

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
    if (str == NULL) {
        LOGGER_DEBUG("Empty destination!");
        return;
    }

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
static inline__ const uint8_t *stringify_error ( MSICallError error_code )
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


/**
 * @brief Convert error_code into string.
 *
 * @param error_code The code.
 * @return const uint8_t* The string.
 */
static inline__ const uint8_t *stringify_error_code ( MSICallError error_code )
{
    static const uint8_t *strings[] = {
        ( uint8_t *) "",
        ( uint8_t *) "1",
        ( uint8_t *) "2",
        ( uint8_t *) "3",
        ( uint8_t *) "4",
        ( uint8_t *) "5",
        ( uint8_t *) "6"
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
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int send_message ( MSISession *session, MSICall *call, MSIMessage *msg, uint32_t to )
{
    msi_msg_set_callid ( msg, call->id, CALL_ID_LEN );

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];
    uint16_t _length = message_to_send ( msg, _msg_string_final );

    if (!_length) {
        LOGGER_WARNING("Parsing message failed; nothing sent!");
        return -1;
    }

    /*
    LOGGER_SCOPE(
        char cast[MSI_MAXMSG_SIZE];
        stringify_message(msg, cast);
        LOGGER_DEBUG("[Call: %s] [to: %u] Sending message: len: %d\n%s", call->id, to, _length, cast);
    );*/


    if ( m_msi_packet(session->messenger_handle, to, _msg_string_final, _length) ) {
        LOGGER_DEBUG("Sent message");
        return 0;
    }

    return -1;
}


/**
 * @brief Determine 'bigger' call id
 *
 * @param first duh
 * @param second duh
 * @return int
 * @retval 0 it's first
 * @retval 1 it's second
 */
int call_id_bigger( const uint8_t *first, const uint8_t *second)
{
    int i = 0;

    for (; i < CALL_ID_LEN; i ++) {

        if ( first[i] != second[i] )
            return first[i] > second [i] ? 0 : 1;
    }
}


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param msg The message.
 * @param peer_id The peer.
 * @return void
 */
void flush_peer_type ( MSICall *call, MSIMessage *msg, int peer_id )
{
    if ( msg->calltype.header_value ) {
        uint8_t hdrval [MSI_MAXMSG_SIZE]; /* Make sure no overflow */

        memcpy(hdrval, msg->calltype.header_value, msg->calltype.size);
        hdrval[msg->calltype.size] = '\0';

        if ( strcmp ( ( const char *) hdrval, CT_AUDIO_HEADER_VALUE ) == 0 ) {
            call->type_peer[peer_id] = type_audio;

        } else if ( strcmp ( ( const char *) hdrval, CT_VIDEO_HEADER_VALUE ) == 0 ) {
            call->type_peer[peer_id] = type_video;
        } else {} /* Error */
    } else {} /* Error */
}

void handle_remote_connection_change(Messenger *messenger, int friend_num, uint8_t status, void *session_p)
{
    MSISession *session = session_p;

    switch ( status ) {
        case 0: { /* Went offline */
            uint32_t j = 0;

            for ( ; j < session->max_calls; j ++ ) {

                if ( !session->calls[j] ) continue;

                int i = 0;

                for ( ; i < session->calls[j]->peer_count; i ++ )
                    if ( session->calls[j]->peers[i] == friend_num ) {
                        invoke_callback(j, MSI_OnPeerTimeout);
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

MSICall *find_call ( MSISession *session, uint8_t *call_id )
{
    if ( call_id == NULL ) return NULL;

    uint32_t i = 0;

    for (; i < session->max_calls; i ++ )
        if ( session->calls[i] && memcmp(session->calls[i]->id, call_id, CALL_ID_LEN) == 0 ) {
            LOGGER_DEBUG("Found call id: %s", session->calls[i]->id);
            return session->calls[i];
        }

    return NULL;
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
int handle_error ( MSISession *session, MSICall *call, MSICallError errid, uint32_t to )
{
    if (!call) {
        LOGGER_WARNING("Cannot handle error on 'null' call");
        return -1;
    }

    LOGGER_DEBUG("Sending error: %d on call: %s", errid, call->id);

    MSIMessage *_msg_error = msi_new_message ( TYPE_RESPONSE, stringify_response ( error ) );

    const uint8_t *_error_code_str = stringify_error_code ( errid );

    msi_msg_set_reason ( _msg_error, _error_code_str, strlen ( ( const char *) _error_code_str ) );
    send_message ( session, call, _msg_error, to );
    free_message ( _msg_error );

    session->last_error_id = errid;
    session->last_error_str = stringify_error ( errid );

    invoke_callback(call->call_idx, MSI_OnError);

    return 0;
}


/**
 * @brief Determine the error if any.
 *
 * @param session Control session.
 * @param msg The message.
 * @return int
 * @retval -1 No error.
 * @retval 0 Error occurred and response sent.
 */
int has_call_error ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !msg->callid.header_value ) {
        return handle_error ( session, call, error_no_callid, msg->friend_id );

    } else if ( !call ) {
        LOGGER_WARNING("Handling message while no call!");
        return 0;

    } else if ( memcmp ( call->id, msg->callid.header_value, CALL_ID_LEN ) != 0 ) {
        return handle_error ( session, call, error_id_mismatch, msg->friend_id );

    }

    return -1;
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
        call->peers = calloc(sizeof(uint32_t), 1);
        call->peer_count = 1;
    } else {
        call->peer_count ++;
        call->peers = realloc( call->peers, sizeof(uint32_t) * call->peer_count);
    }

    call->peers[call->peer_count - 1] = peer_id;

    LOGGER_DEBUG("Added peer: %d", peer_id);
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

    if (peers == 0) {
        LOGGER_ERROR("No peers!");
        return NULL;
    }

    int32_t _call_idx = 0;

    for (; _call_idx < session->max_calls; _call_idx ++) {
        if ( !session->calls[_call_idx] ) {
            session->calls[_call_idx] = calloc ( sizeof ( MSICall ), 1 );
            break;
        }
    }

    if ( _call_idx == session->max_calls ) {
        LOGGER_WARNING("Reached maximum amount of calls!");
        return NULL;
    }


    MSICall *_call = session->calls[_call_idx];

    if ( _call == NULL ) {
        LOGGER_WARNING("Allocation failed!");
        return NULL;
    }

    _call->call_idx = _call_idx;
    _call->type_peer = calloc ( sizeof ( MSICallType ), peers );

    if ( _call->type_peer == NULL ) {
        LOGGER_WARNING("Allocation failed!");
        return NULL;
    }

    _call->session = session;

    /*_call->_participant_count = _peers;*/

    _call->request_timer_id = 0;
    _call->ringing_timer_id = 0;

    _call->key_local = NULL;
    _call->key_peer = NULL;
    _call->nonce_local = NULL;
    _call->nonce_peer = NULL;

    _call->ringing_tout_ms = ringing_timeout;

    pthread_mutex_init ( &_call->mutex, NULL );

    LOGGER_DEBUG("Started new call with index: %u", _call_idx);
    return _call;
}


/**
 * @brief Terminate the call.
 *
 * @param session Control session.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int terminate_call ( MSISession *session, MSICall *call )
{
    if ( !call ) {
        LOGGER_WARNING("Tried to terminate non-existing call!");
        return -1;
    }

    int rc = pthread_mutex_trylock(&session->mutex); /* Lock if not locked */

    LOGGER_DEBUG("Terminated call id: %d", call->call_idx);
    /* Check event loop and cancel timed events if there are any
     * NOTE: This has to be done before possibly
     * locking the mutex the second time
     */
    event.timer_release ( call->request_timer_id );
    event.timer_release ( call->ringing_timer_id );

    /* Get a handle */
    pthread_mutex_lock ( &call->mutex );

    session->calls[call->call_idx] = NULL;

    free ( call->type_peer );
    free ( call->key_local );
    free ( call->key_peer );
    free ( call->peers);

    /* Release handle */
    pthread_mutex_unlock ( &call->mutex );

    pthread_mutex_destroy ( &call->mutex );

    free ( call );

    if ( rc != EBUSY ) /* Unlock if locked by this call */
        pthread_mutex_unlock(&session->mutex);

    return 0;
}


/**
 * @brief Function called at request timeout. If not called in thread it might cause trouble
 *
 * @param arg Control session
 * @return void*
 */
void *handle_timeout ( void *arg )
{
    /* TODO: Cancel might not arrive there; set up
     * timers on these cancels and terminate call on
     * their timeout
     */
    MSICall *_call = arg;

    if (_call) {
        LOGGER_DEBUG("[Call: %s] Request timed out!", _call->id);

        invoke_callback(_call->call_idx, MSI_OnRequestTimeout);
    }

    if ( _call && _call->session ) {

        /* TODO: Cancel all? */
        /* uint16_t _it = 0;
         *       for ( ; _it < _session->call->peer_count; _it++ ) */
        msi_cancel ( _call->session, _call->call_idx, _call->peers [0], "Request timed out" );
        /*terminate_call(_call->session, _call);*/
    }

    pthread_exit(NULL);
}


/********** Request handlers **********/
int handle_recv_invite ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'invite' on call: %s", session, call ? (char *)call->id : "making new");

    pthread_mutex_lock(&session->mutex);


    if ( call ) {
        if ( call->peers[0] == msg->friend_id ) {
            /* The glare case. A calls B when at the same time
             * B calls A. Who has advantage is set bey calculating
             * 'bigger' Call id and then that call id is being used in
             * future. User with 'bigger' Call id has the advantage
             * as in he will wait the response from the other.
             */

            if ( call_id_bigger (call->id, msg->callid.header_value) == 1 ) { /* Peer has advantage */

                /* Terminate call; peer will timeout(call) if call initialization (magically) fails */
                terminate_call(session, call);

                call = init_call ( session, 1, 0 );

                if ( !call ) {
                    pthread_mutex_unlock(&session->mutex);
                    LOGGER_ERROR("Starting call");
                    return 0;
                }

            } else {
                pthread_mutex_unlock(&session->mutex);
                return 0; /* Wait for ringing from peer */
            }

        } else {
            handle_error ( session, call, error_busy, msg->friend_id ); /* TODO: Ugh*/
            pthread_mutex_unlock(&session->mutex);
            return 0;
        }
    } else {
        call = init_call ( session, 1, 0 );

        if ( !call ) {
            pthread_mutex_unlock(&session->mutex);
            LOGGER_ERROR("Starting call");
            return 0;
        }
    }

    if ( !msg->callid.header_value ) {
        handle_error ( session, call, error_no_callid, msg->friend_id );
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    memcpy ( call->id, msg->callid.header_value, CALL_ID_LEN );
    call->state = call_starting;

    add_peer( call, msg->friend_id);

    flush_peer_type ( call, msg, 0 );

    MSIMessage *_msg_ringing = msi_new_message ( TYPE_RESPONSE, stringify_response ( ringing ) );
    send_message ( session, call, _msg_ringing, msg->friend_id );
    free_message ( _msg_ringing );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnInvite);

    return 1;
}
int handle_recv_start ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'start' on call: %s, friend id: %d", session, call->id, msg->friend_id );

    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    if ( !msg->cryptokey.header_value ) {
        int rc = handle_error ( session, call, error_no_crypto_key, msg->friend_id );
        pthread_mutex_unlock(&session->mutex);
        return rc;
    }

    call->state = call_active;

    call->key_peer = calloc ( sizeof ( uint8_t ), crypto_box_KEYBYTES );
    memcpy ( call->key_peer, msg->cryptokey.header_value, crypto_box_KEYBYTES );

    call->nonce_peer = calloc ( sizeof ( uint8_t ), crypto_box_NONCEBYTES );
    memcpy ( call->nonce_peer, msg->nonce.header_value,  crypto_box_NONCEBYTES );

    flush_peer_type ( call, msg, 0 );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnStart);
    return 1;
}
int handle_recv_reject ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'reject' on call: %s", session, call->id);

    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 )  {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }


    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, call, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );


    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnReject);
    /*
    event.timer_release ( session->call->request_timer_id );
    session->call->request_timer_id = event.timer_alloc ( handle_timeout, session, m_deftout );
    */

    terminate_call(session, call);
    return 1;
}
int handle_recv_cancel ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'cancel' on call: %s", session, call->id );

    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    /* Act as end message */
    /*
    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, call, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );*/

    pthread_mutex_unlock(&session->mutex);
    invoke_callback(call->call_idx, MSI_OnCancel);

    terminate_call ( session, call );
    return 1;
}
int handle_recv_end ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    LOGGER_DEBUG("Session: %p Handling 'end' on call: %s", session, call->id );

    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, call, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnEnd);

    terminate_call ( session, call );
    return 1;
}

/********** Response handlers **********/
int handle_recv_ringing ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'ringing' on call: %s", session, call->id );

    call->ringing_timer_id = event.timer_alloc ( handle_timeout, call, call->ringing_tout_ms );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnRinging);
    return 1;
}
int handle_recv_starting ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'starting' on call: %s", session, call->id );


    if ( !msg->cryptokey.header_value ) {
        int rc = handle_error ( session, call, error_no_crypto_key, msg->friend_id );
        pthread_mutex_unlock(&session->mutex);
        return rc;
    }

    /* Generate local key/nonce to send */
    call->key_local = calloc ( sizeof ( uint8_t ), crypto_box_KEYBYTES );
    new_symmetric_key ( call->key_local );

    call->nonce_local = calloc ( sizeof ( uint8_t ), crypto_box_NONCEBYTES );
    new_nonce ( call->nonce_local );

    /* Save peer key/nonce */
    call->key_peer = calloc ( sizeof ( uint8_t ), crypto_box_KEYBYTES );
    memcpy ( call->key_peer, msg->cryptokey.header_value, crypto_box_KEYBYTES );

    call->nonce_peer = calloc ( sizeof ( uint8_t ), crypto_box_NONCEBYTES );
    memcpy ( call->nonce_peer, msg->nonce.header_value,  crypto_box_NONCEBYTES );

    call->state = call_active;

    MSIMessage *_msg_start = msi_new_message ( TYPE_REQUEST, stringify_request ( start ) );
    msi_msg_set_cryptokey ( _msg_start, call->key_local, crypto_box_KEYBYTES );
    msi_msg_set_nonce ( _msg_start, call->nonce_local, crypto_box_NONCEBYTES );
    send_message ( session, call, _msg_start, msg->friend_id );
    free_message ( _msg_start );

    flush_peer_type ( call, msg, 0 );


    event.timer_release ( call->ringing_timer_id );
    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnStarting);
    return 1;
}
int handle_recv_ending ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    pthread_mutex_lock(&session->mutex);

    if ( has_call_error ( session, call, msg ) == 0 ) {
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'ending' on call: %s", session, call->id );

    /* Stop timer */
    event.timer_release ( call->request_timer_id );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnEnding);

    /* Terminate call */
    terminate_call ( session, call );

    return 1;
}
int handle_recv_error ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    pthread_mutex_lock(&session->mutex);

    if ( !call ) {
        LOGGER_WARNING("Handling 'error' on non-existing call!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    LOGGER_DEBUG("Session: %p Handling 'error' on call: %s", session, call->id );

    /* Handle error accordingly */
    if ( msg->reason.header_value ) {
        session->last_error_id = atoi ( ( const char *) msg->reason.header_value );
        session->last_error_str = stringify_error ( session->last_error_id );
        LOGGER_DEBUG("Error reason: %s", session->last_error_str);
    }

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnEnding);

    terminate_call ( session, call );

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
    LOGGER_DEBUG("Got msi message");
    /* Unused */
    (void)messenger;

    MSISession *_session = object;
    MSIMessage *_msg;

    if ( !length ) {
        LOGGER_WARNING("Lenght param negative");
        return;
    }

    _msg = parse_message ( data, length );

    if ( !_msg ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }

    _msg->friend_id = source;


    /* Find what call */
    MSICall *_call = _msg->callid.header_value ? find_call(_session, _msg->callid.header_value ) : NULL;

    /* Now handle message */

    if ( _msg->request.header_value ) { /* Handle request */

        if ( _msg->response.size > 32 ) {
            LOGGER_WARNING("Header size too big");
            goto free_end;
        }

        uint8_t _request_value[32];

        memcpy(_request_value, _msg->request.header_value, _msg->request.size);
        _request_value[_msg->request.size] = '\0';

        if ( same ( _request_value, stringify_request ( invite ) ) ) {
            handle_recv_invite ( _session, _call, _msg );

        } else if ( same ( _request_value, stringify_request ( start ) ) ) {
            handle_recv_start ( _session, _call, _msg );

        } else if ( same ( _request_value, stringify_request ( cancel ) ) ) {
            handle_recv_cancel ( _session, _call, _msg );

        } else if ( same ( _request_value, stringify_request ( reject ) ) ) {
            handle_recv_reject ( _session, _call, _msg );

        } else if ( same ( _request_value, stringify_request ( end ) ) ) {
            handle_recv_end ( _session, _call, _msg );
        } else {
            LOGGER_WARNING("Uknown request");
            goto free_end;
        }

    } else if ( _msg->response.header_value ) { /* Handle response */

        if ( _msg->response.size > 32 ) {
            LOGGER_WARNING("Header size too big");
            goto free_end;
        }

        /* Got response so cancel timer */
        if ( _call )
            event.timer_release ( _call->request_timer_id );

        uint8_t _response_value[32];

        memcpy(_response_value, _msg->response.header_value, _msg->response.size);
        _response_value[_msg->response.size] = '\0';

        if ( same ( _response_value, stringify_response ( ringing ) ) ) {
            handle_recv_ringing ( _session, _call, _msg );

        } else if ( same ( _response_value, stringify_response ( starting ) ) ) {
            handle_recv_starting ( _session, _call, _msg );

        } else if ( same ( _response_value, stringify_response ( ending ) ) ) {
            handle_recv_ending ( _session, _call, _msg );

        } else if ( same ( _response_value, stringify_response ( error ) ) ) {
            handle_recv_error ( _session, _call, _msg );

        } else {
            LOGGER_WARNING("Uknown response");
            goto free_end;
        }

    } else {
        LOGGER_WARNING("Invalid message: no resp nor requ headers");
    }

free_end:
    free_message ( _msg );
}


/**
 * @brief Callback setter.
 *
 * @param callback The callback.
 * @param id The id.
 * @return void
 */
void msi_register_callback ( MSICallback callback, MSICallbackID id, void *userdata )
{
    callbacks[id].function = callback;
    callbacks[id].data = userdata;
}


/**
 * @brief Start the control session.
 *
 * @param messenger Tox* object.
 * @param max_calls Amount of calls possible
 * @return MSISession* The created session.
 * @retval NULL Error occurred.
 */
MSISession *msi_init_session ( Messenger *messenger, int32_t max_calls )
{
    if (messenger == NULL) {
        LOGGER_ERROR("Could not init session on empty messenger!");
        return NULL;
    }

    if ( !max_calls) return NULL;

    MSISession *_retu = calloc ( sizeof ( MSISession ), 1 );

    if (_retu == NULL) {
        LOGGER_ERROR("Allocation failed!");
        return NULL;
    }

    _retu->messenger_handle = messenger;
    _retu->agent_handler = NULL;

    _retu->calls = calloc( sizeof (MSICall *), max_calls );
    _retu->max_calls = max_calls;

    _retu->frequ = 10000; /* default value? */
    _retu->call_timeout = 30000; /* default value? */


    m_callback_msi_packet(messenger, msi_handle_packet, _retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, _retu);

    pthread_mutex_init(&_retu->mutex, NULL);

    LOGGER_DEBUG("New msi session: %p max calls: %u", _retu, max_calls);
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
    if (session == NULL) {
        LOGGER_ERROR("Tried to terminate non-existing session");
        return -1;
    }

    pthread_mutex_lock(&session->mutex);
    m_callback_msi_packet((struct Messenger *) session->messenger_handle, NULL, NULL);
    pthread_mutex_unlock(&session->mutex);

    int _status = 0;

    /* If have calls, cancel them */
    uint32_t idx = 0;

    for (; idx < session->max_calls; idx ++) if ( session->calls[idx] ) {
            /* Cancel all? */
            uint16_t _it = 0;
            /*for ( ; _it < session->calls[idx]->peer_count; _it++ )
             * FIXME: will not work on multiple peers, must cancel call for all peers
             */
            msi_cancel ( session, idx, session->calls[idx]->peers [_it], "MSI session terminated!" );
        }


    pthread_mutex_destroy(&session->mutex);

    LOGGER_DEBUG("Terminated session: %p", session);
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
int msi_invite ( MSISession *session, int32_t *call_index, MSICallType call_type, uint32_t rngsec, uint32_t friend_id )
{
    pthread_mutex_lock(&session->mutex);

    LOGGER_DEBUG("Session: %p Inviting friend: %u", session, friend_id);


    MSICall *_call = init_call ( session, 1, rngsec ); /* Just one peer for now */

    if ( !_call ) {
        pthread_mutex_unlock(&session->mutex);
        LOGGER_ERROR("Cannot handle more calls");
        return -1;
    }

    *call_index = _call->call_idx;

    t_randomstr ( _call->id, CALL_ID_LEN );

    add_peer(_call, friend_id );

    _call->type_local = call_type;

    MSIMessage *_msg_invite = msi_new_message ( TYPE_REQUEST, stringify_request ( invite ) );

    /* Do whatever with message */
    if ( call_type == type_audio ) {
        msi_msg_set_calltype ( _msg_invite, ( const uint8_t *) CT_AUDIO_HEADER_VALUE, strlen ( CT_AUDIO_HEADER_VALUE ) );
    } else {
        msi_msg_set_calltype ( _msg_invite, ( const uint8_t *) CT_VIDEO_HEADER_VALUE, strlen ( CT_VIDEO_HEADER_VALUE ) );
    }

    send_message ( session, _call, _msg_invite, friend_id );
    free_message ( _msg_invite );

    _call->state = call_inviting;

    _call->request_timer_id = event.timer_alloc ( handle_timeout, _call, m_deftout );

    LOGGER_DEBUG("Invite sent");

    pthread_mutex_unlock(&session->mutex);

    return 0;
}


/**
 * @brief Hangup active call.
 *
 * @param session Control session.
 * @param call_id To which call is this action handled.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int msi_hangup ( MSISession *session, int32_t call_index )
{
    pthread_mutex_lock(&session->mutex);
    LOGGER_DEBUG("Session: %p Hanging up call: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    if ( !session->calls[call_index] || session->calls[call_index]->state != call_active ) {
        LOGGER_ERROR("No call with such index or call is not active!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    MSIMessage *_msg_end = msi_new_message ( TYPE_REQUEST, stringify_request ( end ) );

    /* hangup for each peer */
    int _it = 0;

    for ( ; _it < session->calls[call_index]->peer_count; _it ++ )
        send_message ( session, session->calls[call_index], _msg_end, session->calls[call_index]->peers[_it] );


    free_message ( _msg_end );

    session->calls[call_index]->request_timer_id = event.timer_alloc ( handle_timeout, session->calls[call_index],
            m_deftout );

    pthread_mutex_unlock(&session->mutex);
    return 0;
}


/**
 * @brief Answer active call request.
 *
 * @param session Control session.
 * @param call_id To which call is this action handled.
 * @param call_type Answer with Audio or Video(both).
 * @return int
 */
int msi_answer ( MSISession *session, int32_t call_index, MSICallType call_type )
{
    pthread_mutex_lock(&session->mutex);
    LOGGER_DEBUG("Session: %p Answering call: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    MSIMessage *_msg_starting = msi_new_message ( TYPE_RESPONSE, stringify_response ( starting ) );

    session->calls[call_index]->type_local = call_type;

    if ( call_type == type_audio ) {
        msi_msg_set_calltype
        ( _msg_starting, ( const uint8_t *) CT_AUDIO_HEADER_VALUE, strlen ( CT_AUDIO_HEADER_VALUE ) );
    } else {
        msi_msg_set_calltype
        ( _msg_starting, ( const uint8_t *) CT_VIDEO_HEADER_VALUE, strlen ( CT_VIDEO_HEADER_VALUE ) );
    }

    /* Now set the local encryption key and pass it with STARTING message */

    session->calls[call_index]->key_local = calloc ( sizeof ( uint8_t ), crypto_box_KEYBYTES );
    new_symmetric_key ( session->calls[call_index]->key_local );

    session->calls[call_index]->nonce_local = calloc ( sizeof ( uint8_t ), crypto_box_NONCEBYTES );
    new_nonce ( session->calls[call_index]->nonce_local );

    msi_msg_set_cryptokey ( _msg_starting, session->calls[call_index]->key_local, crypto_box_KEYBYTES );
    msi_msg_set_nonce ( _msg_starting, session->calls[call_index]->nonce_local, crypto_box_NONCEBYTES );

    send_message ( session, session->calls[call_index], _msg_starting,
                   session->calls[call_index]->peers[session->calls[call_index]->peer_count - 1] );
    free_message ( _msg_starting );

    session->calls[call_index]->state = call_active;

    pthread_mutex_unlock(&session->mutex);
    return 0;
}


/**
 * @brief Cancel request.
 *
 * @param session Control session.
 * @param call_id To which call is this action handled.
 * @param reason Set optional reason header. Pass NULL if none.
 * @return int
 */
int msi_cancel ( MSISession *session, int32_t call_index, uint32_t peer, const char *reason )
{
    pthread_mutex_lock(&session->mutex);
    LOGGER_DEBUG("Session: %p Canceling call: %u; reason:", session, call_index, reason ? reason : "Unknown");

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    MSIMessage *_msg_cancel = msi_new_message ( TYPE_REQUEST, stringify_request ( cancel ) );

    if ( reason ) msi_msg_set_reason(_msg_cancel, (const uint8_t *)reason, strlen(reason));

    send_message ( session, session->calls[call_index], _msg_cancel, peer );
    free_message ( _msg_cancel );

    /*session->calls[call_index]->request_timer_id = event.timer_alloc ( handle_timeout, session->calls[call_index], m_deftout );*/
    terminate_call ( session, session->calls[call_index] );
    pthread_mutex_unlock(&session->mutex);

    return 0;
}


/**
 * @brief Reject request.
 *
 * @param session Control session.
 * @param call_id To which call is this action handled.
 * @return int
 */
int msi_reject ( MSISession *session, int32_t call_index, const uint8_t *reason )
{
    pthread_mutex_lock(&session->mutex);
    LOGGER_DEBUG("Session: %p Rejecting call: %u; reason:", session, call_index, reason ? (char *)reason : "Unknown");

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        LOGGER_ERROR("Invalid call index!");
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    MSIMessage *_msg_reject = msi_new_message ( TYPE_REQUEST, stringify_request ( reject ) );

    if ( reason ) msi_msg_set_reason(_msg_reject, reason, strlen((const char *)reason) + 1);

    send_message ( session, session->calls[call_index], _msg_reject,
                   session->calls[call_index]->peers[session->calls[call_index]->peer_count - 1] );
    free_message ( _msg_reject );

    session->calls[call_index]->request_timer_id = event.timer_alloc ( handle_timeout, session->calls[call_index],
            m_deftout );

    pthread_mutex_unlock(&session->mutex);
    return 0;
}


/**
 * @brief Terminate the current call.
 *
 * @param session Control session.
 * @param call_id To which call is this action handled.
 * @return int
 */
int msi_stopcall ( MSISession *session, int32_t call_index )
{
    pthread_mutex_lock(&session->mutex);
    LOGGER_DEBUG("Session: %p Stopping call index: %u", session, call_index);

    if ( call_index < 0 || call_index >= session->max_calls || !session->calls[call_index] ) {
        pthread_mutex_unlock(&session->mutex);
        return -1;
    }

    /* just terminate it */

    terminate_call ( session, session->calls[call_index] );

    pthread_mutex_unlock(&session->mutex);
    return 0;
}
