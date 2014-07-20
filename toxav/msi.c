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

    struct _MSIMessage *next;

    int friend_id;

} MSIMessage;


static struct _Callbacks {
    MSICallback function;
    void *data;
} callbacks[11] = {{0}};

inline__ void invoke_callback(int32_t call_index, MSICallbackID id)
{
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
static int parse_raw_data ( MSIMessage *msg, const uint8_t *data, uint16_t length )
{

#define ON_HEADER(iterator, size_con, header, descriptor, type_size_const) \
( memcmp(iterator, descriptor, type_size_const) == 0){ /* Okay */ \
iterator += type_size_const; /* Set iterator at begining of value part */ \
if ( *iterator != value_byte || size_con <= type_size_const) { return -1; } size_con -= type_size_const; \
iterator ++; if(size_con <= 3) {return -1;} size_con -= 3; \
uint16_t _value_size; memcpy(&_value_size, iterator, sizeof(_value_size)); _value_size = ntohs(_value_size);\
if(size_con < _value_size) { return -1; } size_con -= _value_size; \
if ( !(header.header_value = calloc(sizeof(uint8_t), _value_size)) ) \
LOGGER_ERROR("Allocation failed! Program might misbehave!"); \
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

            switch ( _size ) { /* Compare the size of the hardcoded values ( very convenient ) */

                case 4: { /* INFO header */
                    if ON_HEADER ( _it, size_max, msg->info, INFO_FIELD, 4 )
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
if (!(var.header_value = calloc(sizeof *mheader_value, t_size))) \
{ LOGGER_WARNING("Header allocation failed! Program might misbehave!"); } \
else { memcpy(var.header_value, mheader_value, t_size); \
var.size = t_size; }


/**
 * @brief Speaks for it self.
 *
 * @param msg The message.
 * @return void
 */
static void free_message ( MSIMessage *msg )
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
static MSIMessage *msi_new_message ( uint8_t type, const uint8_t *type_id )
{
    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( _retu == NULL ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
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
static MSIMessage *parse_message ( const uint8_t *data, uint16_t length )
{
    if ( data == NULL ) {
        LOGGER_WARNING("Tried to parse empty message!");
        return NULL;
    }

    MSIMessage *_retu = calloc ( sizeof ( MSIMessage ), 1 );

    if ( _retu == NULL ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
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
 * @brief Speaks for it self.
 *
 * @param dest Container.
 * @param header_field Field.
 * @param header_value Field value.
 * @param value_len Length of field value.
 * @param length Pointer to container length.
 * @return uint8_t* Iterated container.
 */
static uint8_t *append_header_to_string (
    uint8_t *dest,
    const uint8_t *header_field,
    const uint8_t *header_value,
    uint16_t value_len,
    uint16_t *length )
{
    if ( dest == NULL ) {
        LOGGER_ERROR("No destination space!");
        return NULL;
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
static uint16_t message_to_send ( MSIMessage *msg, uint8_t *dest )
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

    *_iterated = end_byte;
    _size ++;

    return _size;
}


#define GENERIC_SETTER_DEFINITION(header) \
void msi_msg_set_##header ( MSIMessage* _msg, const uint8_t* header_value, uint16_t _size ) \
{ if ( !_msg || !header_value) { LOGGER_WARNING("No setter values!"); return; } \
  free(_msg->header.header_value); \
  ALLOCATE_HEADER( _msg->header, header_value, _size )}

GENERIC_SETTER_DEFINITION ( calltype )
GENERIC_SETTER_DEFINITION ( reason )
GENERIC_SETTER_DEFINITION ( info )
GENERIC_SETTER_DEFINITION ( callid )




typedef struct _Timer {
    void *(*func)(void *);
    void *func_arg1;
    int func_arg2;
    uint64_t timeout;
    size_t idx;

} Timer;

typedef struct _TimerHandler {
    Timer **timers;
    pthread_mutex_t mutex;

    size_t max_capacity;
    size_t size;
    uint64_t resolution;

    _Bool running;

} TimerHandler;

struct timer_function_args {
    void *arg1;
    int  arg2;
};

/**
 * @brief Allocate timer in array
 *
 * @param timers_container Handler
 * @param func Function to be executed
 * @param arg Its args
 * @param timeout Timeout in ms
 * @return int
 */
static int timer_alloc ( TimerHandler *timers_container, void *(func)(void *), void *arg1, int arg2, unsigned timeout)
{
    static int timer_id;
    pthread_mutex_lock(&timers_container->mutex);

    int i = 0;

    for (; i < timers_container->max_capacity && timers_container->timers[i]; i ++);

    if (i == timers_container->max_capacity) {
        LOGGER_WARNING("Maximum capacity reached!");
        pthread_mutex_unlock(&timers_container->mutex);
        return -1;
    }

    Timer *timer = timers_container->timers[i] = calloc(sizeof(Timer), 1);

    if (timer == NULL) {
        LOGGER_ERROR("Failed to allocate timer!");
        pthread_mutex_unlock(&timers_container->mutex);
        return -1;
    }

    timers_container->size ++;

    timer->func = func;
    timer->func_arg1 = arg1;
    timer->func_arg2 = arg2;
    timer->timeout = timeout + current_time_monotonic(); /* In ms */
    ++timer_id;
    timer->idx = timer_id;

    /* reorder */
    if (i) {
        int j = i - 1;

        for (; j >= 0 && timeout < timers_container->timers[j]->timeout; j--) {
            Timer *tmp = timers_container->timers[j];
            timers_container->timers[j] = timer;
            timers_container->timers[j + 1] = tmp;
        }
    }

    pthread_mutex_unlock(&timers_container->mutex);

    LOGGER_DEBUG("Allocated timer index: %d timeout: %d, current size: %d", i, timeout, timers_container->size);
    return timer->idx;
}

/**
 * @brief Remove timer from array
 *
 * @param timers_container handler
 * @param idx timer id
 * @param lock_mutex (does the mutex need to be locked)
 * @return int
 */
static int timer_release ( TimerHandler *timers_container, int idx , int lock_mutex)
{
    if (lock_mutex)
        pthread_mutex_lock(&timers_container->mutex);

    Timer **timed_events = timers_container->timers;

    int i, res = -1;

    for (i = 0; i < timers_container->max_capacity; ++i) {
        if (timed_events[i] && timed_events[i]->idx == idx) {
            res = i;
            break;
        }
    }

    if (res == -1) {
        LOGGER_WARNING("No event with id: %d", idx);

        if (lock_mutex) pthread_mutex_unlock(&timers_container->mutex);

        return -1;
    }

    free(timed_events[res]);

    timed_events[res] = NULL;

    i = res + 1;

    for (; i < timers_container->max_capacity && timed_events[i]; i ++) {
        timed_events[i - 1] = timed_events[i];
        timed_events[i] = NULL;
    }

    timers_container->size--;

    LOGGER_DEBUG("Popped index: %d, current size: %d ", idx, timers_container->size);

    if (lock_mutex) pthread_mutex_unlock(&timers_container->mutex);

    return 0;
}

/**
 * @brief Main poll for timer execution
 *
 * @param arg ...
 * @return void*
 */
static void *timer_poll( void *arg )
{
    TimerHandler *handler = arg;

    while ( handler->running ) {

        pthread_mutex_lock(&handler->mutex);

        if ( handler->running ) {

            uint64_t time = current_time_monotonic();

            if ( handler->timers[0] && handler->timers[0]->timeout < time ) {
                pthread_t _tid;

                struct timer_function_args *args = malloc(sizeof(struct timer_function_args));
                args->arg1 = handler->timers[0]->func_arg1;
                args->arg2 = handler->timers[0]->func_arg2;

                if ( 0 != pthread_create(&_tid, NULL, handler->timers[0]->func, args) ||
                        0 != pthread_detach(_tid) ) {
                    LOGGER_ERROR("Failed to execute timer at: %d!", handler->timers[0]->timeout);
                    free(args);
                } else {
                    LOGGER_DEBUG("Exectued timer assigned at: %d", handler->timers[0]->timeout);
                }

                timer_release(handler, handler->timers[0]->idx, 0);
            }

        }

        pthread_mutex_unlock(&handler->mutex);

        usleep(handler->resolution);
    }

    pthread_exit(NULL);
}

/**
 * @brief Start timer poll and return handler
 *
 * @param max_capacity capacity
 * @param resolution ...
 * @return TimerHandler*
 */
static TimerHandler *timer_init_session (int max_capacity, int resolution)
{
    TimerHandler *handler = calloc(1, sizeof(TimerHandler));

    if (handler == NULL) {
        LOGGER_ERROR("Failed to allocate memory, program might misbehave!");
        return NULL;
    }

    handler->timers = calloc(max_capacity, sizeof(Timer *));

    if (handler->timers == NULL) {
        LOGGER_ERROR("Failed to allocate %d timed events!", max_capacity);
        free(handler);
        return NULL;
    }

    handler->max_capacity = max_capacity;
    handler->running = 1;
    handler->resolution = resolution;

    pthread_mutex_init(&handler->mutex, NULL);


    pthread_t _tid;

    if ( 0 != pthread_create(&_tid, NULL, timer_poll, handler) || 0 != pthread_detach(_tid) ) {
        LOGGER_ERROR("Failed to start timer poll thread!");
        free(handler->timers);
        free(handler);
        return NULL;
    }

    return handler;
}

/**
 * @brief Terminate timer session
 *
 * @param handler The timer handler
 * @return void
 */
static void timer_terminate_session(TimerHandler *handler)
{
    pthread_mutex_lock(&handler->mutex);

    handler->running = 0;

    pthread_mutex_unlock(&handler->mutex);

    int i = 0;

    for (; i < handler->max_capacity; i ++)
        free(handler->timers[i]);

    free(handler->timers);

    pthread_mutex_destroy( &handler->mutex );
}

/**
 * @brief Generate _random_ alphanumerical string.
 *
 * @param str Destination.
 * @param size Size of string.
 * @return void
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
static int send_message ( MSISession *session, MSICall *call, MSIMessage *msg, uint32_t to )
{
    msi_msg_set_callid ( msg, call->id, CALL_ID_LEN );

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];
    uint16_t _length = message_to_send ( msg, _msg_string_final );

    if (!_length) {
        LOGGER_WARNING("Parsing message failed; nothing sent!");
        return -1;
    }

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
static int call_id_bigger( const uint8_t *first, const uint8_t *second)
{
    return (memcmp(first, second, CALL_ID_LEN) < 0);
}


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param msg The message.
 * @param peer_id The peer.
 * @return void
 */
static void flush_peer_type ( MSICall *call, MSIMessage *msg, int peer_id )
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

static int terminate_call ( MSISession *session, MSICall *call );

static void handle_remote_connection_change(Messenger *messenger, int friend_num, uint8_t status, void *session_p)
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

static MSICall *find_call ( MSISession *session, uint8_t *call_id )
{
    if ( call_id == NULL ) return NULL;

    uint32_t i = 0;

    for (; i < session->max_calls; i ++ )
        if ( session->calls[i] && memcmp(session->calls[i]->id, call_id, CALL_ID_LEN) == 0 ) {
            LOGGER_SCOPE(
                char tmp[CALL_ID_LEN + 1] = {'\0'};
                memcpy(tmp, session->calls[i]->id, CALL_ID_LEN);
                LOGGER_DEBUG("Found call id: %s", tmp);
            );
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
 * @retval -1/0 It's usually always success.
 */
static int send_error ( MSISession *session, MSICall *call, MSICallError errid, uint32_t to )
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

    /* invoke_callback(call->call_idx, MSI_OnError); */

    return 0;
}



/**
 * @brief Add peer to peer list.
 *
 * @param call What call.
 * @param peer_id Its id.
 * @return void
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


/**
 * @brief Speaks for it self.
 *
 * @param session Control session.
 * @param peers Amount of peers. (Currently it only supports 1)
 * @param ringing_timeout Ringing timeout.
 * @return MSICall* The created call.
 */
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

    if ( !(call->type_peer = calloc ( sizeof ( MSICallType ), peers )) ) {
        LOGGER_WARNING("Allocation failed! Program might misbehave!");
        free(call);
        return NULL;
    }

    call->session = session;

    /*_call->_participant_count = _peers;*/

    call->request_timer_id = 0;
    call->ringing_timer_id = 0;

    call->ringing_tout_ms = ringing_timeout;

    pthread_mutex_init ( &call->mutex, NULL );

    LOGGER_DEBUG("Started new call with index: %u", call_idx);
    return call;
}


/**
 * @brief Terminate the call.
 *
 * @param session Control session.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
static int terminate_call ( MSISession *session, MSICall *call )
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
    timer_release ( session->timer_handler, call->request_timer_id, 1);
    timer_release ( session->timer_handler, call->ringing_timer_id, 1);

    /* Get a handle */
    pthread_mutex_lock ( &call->mutex );

    session->calls[call->call_idx] = NULL;

    free ( call->type_peer );
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
static void *handle_timeout ( void *arg )
{
    /* TODO: Cancel might not arrive there; set up
     * timers on these cancels and terminate call on
     * their timeout
     */
    struct timer_function_args *args = arg;
    int call_index = args->arg2;
    MSISession *session = args->arg1;
    MSICall *_call = session->calls[call_index];

    if (_call) {
        LOGGER_DEBUG("[Call: %s] Request timed out!", _call->id);

        invoke_callback(call_index, MSI_OnRequestTimeout);
    }

    if ( _call && _call->session ) {

        /* TODO: Cancel all? */
        /* uint16_t _it = 0;
         *       for ( ; _it < _session->call->peer_count; _it++ ) */
        msi_cancel ( _call->session, _call->call_idx, _call->peers [0], "Request timed out" );
        /*terminate_call(_call->session, _call);*/
    }

    free(arg);
    pthread_exit(NULL);
}


/********** Request handlers **********/
static int handle_recv_invite ( MSISession *session, MSICall *call, MSIMessage *msg )
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
            send_error ( session, call, error_busy, msg->friend_id ); /* TODO: Ugh*/
            terminate_call(session, call);
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
        send_error ( session, call, error_no_callid, msg->friend_id );
        terminate_call(session, call);
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

static int handle_recv_start ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'start' on call: %s, friend id: %d", session, call->id, msg->friend_id );

    pthread_mutex_lock(&session->mutex);

    call->state = call_active;

    flush_peer_type ( call, msg, 0 );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnStart);
    return 1;
}

static int handle_recv_reject ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'reject' on call: %s", session, call->id);

    pthread_mutex_lock(&session->mutex);

    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, call, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );


    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnReject);

    terminate_call(session, call);
    return 1;
}

static int handle_recv_cancel ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'cancel' on call: %s", session, call->id );

    pthread_mutex_lock(&session->mutex);

    /* Act as end message */

    pthread_mutex_unlock(&session->mutex);
    invoke_callback(call->call_idx, MSI_OnCancel);

    terminate_call ( session, call );
    return 1;
}

static int handle_recv_end ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'end' on call: %s", session, call->id );

    pthread_mutex_lock(&session->mutex);

    MSIMessage *_msg_ending = msi_new_message ( TYPE_RESPONSE, stringify_response ( ending ) );
    send_message ( session, call, _msg_ending, msg->friend_id );
    free_message ( _msg_ending );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnEnd);

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

    pthread_mutex_lock(&session->mutex);

    if ( call->ringing_timer_id ) {
        LOGGER_WARNING("Call already ringing");
        pthread_mutex_unlock(&session->mutex);
        return 0;
    }

    LOGGER_DEBUG("Session: %p Handling 'ringing' on call: %s", session, call->id );

    call->ringing_timer_id = timer_alloc ( session->timer_handler, handle_timeout, session, call->call_idx,
                                           call->ringing_tout_ms );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnRinging);
    return 1;
}
static int handle_recv_starting ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    pthread_mutex_lock(&session->mutex);

    LOGGER_DEBUG("Session: %p Handling 'starting' on call: %s", session, call->id );

    call->state = call_active;

    MSIMessage *_msg_start = msi_new_message ( TYPE_REQUEST, stringify_request ( start ) );
    send_message ( session, call, _msg_start, msg->friend_id );
    free_message ( _msg_start );

    flush_peer_type ( call, msg, 0 );


    timer_release ( session->timer_handler, call->ringing_timer_id, 1 );
    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnStarting);
    return 1;
}
static int handle_recv_ending ( MSISession *session, MSICall *call, MSIMessage *msg )
{
    if ( !call ) {
        LOGGER_WARNING("Session: %p Handling 'start' on no call");
        return 0;
    }

    pthread_mutex_lock(&session->mutex);

    LOGGER_DEBUG("Session: %p Handling 'ending' on call: %s", session, call->id );

    /* Stop timer */
    timer_release ( session->timer_handler, call->request_timer_id, 1 );

    pthread_mutex_unlock(&session->mutex);

    invoke_callback(call->call_idx, MSI_OnEnding);

    /* Terminate call */
    terminate_call ( session, call );

    return 1;
}
static int handle_recv_error ( MSISession *session, MSICall *call, MSIMessage *msg )
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
static void msi_handle_packet ( Messenger *messenger, int source, const uint8_t *data, uint16_t length, void *object )
{
    LOGGER_DEBUG("Got msi message");
    /* Unused */
    (void)messenger;

    MSISession *session = object;
    MSIMessage *msg;

    if ( !length ) {
        LOGGER_WARNING("Lenght param negative");
        return;
    }

    msg = parse_message ( data, length );

    if ( !msg ) {
        LOGGER_WARNING("Error parsing message");
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }

    msg->friend_id = source;


    /* Find what call */
    MSICall *call = msg->callid.header_value ? find_call(session, msg->callid.header_value ) : NULL;

    /* Now handle message */

    if ( msg->request.header_value ) { /* Handle request */

        if ( msg->response.size > 32 ) {
            LOGGER_WARNING("Header size too big");
            goto free_end;
        }

        uint8_t _request_value[32];

        memcpy(_request_value, msg->request.header_value, msg->request.size);
        _request_value[msg->request.size] = '\0';

        if ( same ( _request_value, stringify_request ( invite ) ) ) {
            handle_recv_invite ( session, call, msg );

        } else if ( same ( _request_value, stringify_request ( start ) ) ) {
            handle_recv_start ( session, call, msg );

        } else if ( same ( _request_value, stringify_request ( cancel ) ) ) {
            handle_recv_cancel ( session, call, msg );

        } else if ( same ( _request_value, stringify_request ( reject ) ) ) {
            handle_recv_reject ( session, call, msg );

        } else if ( same ( _request_value, stringify_request ( end ) ) ) {
            handle_recv_end ( session, call, msg );
        } else {
            LOGGER_WARNING("Uknown request");
            goto free_end;
        }

    } else if ( msg->response.header_value ) { /* Handle response */

        if ( msg->response.size > 32 ) {
            LOGGER_WARNING("Header size too big");
            goto free_end;
        }

        /* Got response so cancel timer */
        if ( call ) timer_release ( session->timer_handler, call->request_timer_id, 1 );

        uint8_t _response_value[32];

        memcpy(_response_value, msg->response.header_value, msg->response.size);
        _response_value[msg->response.size] = '\0';

        if ( same ( _response_value, stringify_response ( ringing ) ) ) {
            handle_recv_ringing ( session, call, msg );

        } else if ( same ( _response_value, stringify_response ( starting ) ) ) {
            handle_recv_starting ( session, call, msg );

        } else if ( same ( _response_value, stringify_response ( ending ) ) ) {
            handle_recv_ending ( session, call, msg );

        } else if ( same ( _response_value, stringify_response ( error ) ) ) {
            handle_recv_error ( session, call, msg );

        } else {
            LOGGER_WARNING("Uknown response");
            goto free_end;
        }

    } else {
        LOGGER_WARNING("Invalid message: no resp nor requ headers");
    }

free_end:
    free_message ( msg );
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

    TimerHandler *handler = timer_init_session(max_calls * 10, 10000);

    if ( !max_calls || !handler ) {
        LOGGER_WARNING("Invalid max call treshold or timer handler initialization failed!");
        return NULL;
    }

    MSISession *retu = calloc ( sizeof ( MSISession ), 1 );

    if (retu == NULL) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        return NULL;
    }

    retu->messenger_handle = messenger;
    retu->agent_handler = NULL;
    retu->timer_handler = handler;

    if (!(retu->calls = calloc( sizeof (MSICall *), max_calls ))) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        free(retu);
        return NULL;
    }

    retu->max_calls = max_calls;

    retu->frequ = 10000; /* default value? */
    retu->call_timeout = 30000; /* default value? */


    m_callback_msi_packet(messenger, msi_handle_packet, retu );

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(messenger, handle_remote_connection_change, retu);

    pthread_mutex_init(&retu->mutex, NULL);

    LOGGER_DEBUG("New msi session: %p max calls: %u", retu, max_calls);
    return retu;
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

    timer_terminate_session(session->timer_handler);

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

    _call->request_timer_id = timer_alloc ( session->timer_handler, handle_timeout, session, _call->call_idx, m_deftout );

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

    session->calls[call_index]->state = call_hanged_up;

    free_message ( _msg_end );

    session->calls[call_index]->request_timer_id =
        timer_alloc ( session->timer_handler, handle_timeout, session, call_index, m_deftout );

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

    /*session->calls[call_index]->state = call_hanged_up;
      session->calls[call_index]->request_timer_id = timer_alloc ( handle_timeout, session, call_index, m_deftout );*/
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

    session->calls[call_index]->state = call_hanged_up;

    session->calls[call_index]->request_timer_id =
        timer_alloc ( session->timer_handler, handle_timeout, session, call_index, m_deftout );

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
