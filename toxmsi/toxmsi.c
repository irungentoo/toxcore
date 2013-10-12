
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE

#include "toxmsi.h"
#include "toxmsi_event.h"
#include "toxmsi_message.h"
#include "../toxrtp/toxrtp_helper.h"
#include "../toxcore/network.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>

#define same(x, y) strcmp((const char*) x, (const char*) y) == 0

typedef enum {
    error_deadcall = 1,   /* has call id but it's from old call */
    error_id_mismatch, /* non-existing call */

    error_no_callid,      /* not having call id */
    error_no_call,         /* no call in session */

    error_busy
} msi_error_t; /* Error codes */

static inline const uint8_t *stringify_error(msi_error_t _error_code)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"",
        (uint8_t*)"Using dead call",
        (uint8_t*)"Call id not set to any call",
        (uint8_t*)"Call id not available",
        (uint8_t*)"No active call in session",
        (uint8_t*)"Callee busy"
    };

    return strings[_error_code];
}

static inline const uint8_t *stringify_error_code(msi_error_t _error_code)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"",
        (uint8_t*)"1",
        (uint8_t*)"2",
        (uint8_t*)"3",
        (uint8_t*)"4",
        (uint8_t*)"5"
    };

    return strings[_error_code];
}

/* ******************* */
/* --------- GLOBAL FUNCTIONS USED BY THIS FILE --------- */

/* CALLBACKS */
/*int (*msi_send_message_callback) ( int, uint8_t*, uint32_t ) = NULL;*/
int ( *msi_send_message_callback ) ( void* _core_handler, tox_IP_Port,  uint8_t*, uint32_t ) = NULL;
int ( *msi_recv_message_callback ) ( tox_IP_Port*, uint8_t*, uint32_t* ) = NULL;

MCBTYPE ( *msi_recv_invite_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_start_call_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_reject_call_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_cancel_call_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_end_call_callback ) ( MCBARGS ) = NULL;

MCBTYPE ( *msi_ringing_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_starting_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_ending_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_error_callback ) ( MCBARGS ) = NULL;

MCBTYPE ( *msi_timeout_callback ) ( MCBARGS ) = NULL;
/* End of CALLBACKS */

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

/* REGISTER CALLBACKS */
/*void msi_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) )*/
void msi_register_callback_send ( int ( *callback ) ( void* _core_handler, tox_IP_Port, uint8_t*, uint32_t ) )
{
    msi_send_message_callback = callback;
}

void msi_register_callback_recv ( int ( *callback ) ( tox_IP_Port*, uint8_t*, uint32_t* ) )
{
    msi_recv_message_callback = callback;
}

/* Function to be called when received invite.
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_recv_invite ( MCALLBACK )
{
    msi_recv_invite_callback = callback;
}

/* Function to be called when the call is started
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_started ( MCALLBACK )
{
    msi_start_call_callback = callback;
}

/* Function to be called when call is rejected
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_rejected ( MCALLBACK )
{
    msi_reject_call_callback = callback;
}

/* Function to be called when call is canceled
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_canceled ( MCALLBACK )
{
    msi_cancel_call_callback = callback;
}

void msi_register_callback_call_ended ( MCALLBACK )
{
    msi_end_call_callback = callback;
}


/* Functions to be called when gotten x response */

void msi_register_callback_recv_ringing ( MCALLBACK )
{
    msi_ringing_callback = callback;
}
void msi_register_callback_recv_starting ( MCALLBACK )
{
    msi_starting_callback = callback;
}
void msi_register_callback_recv_ending ( MCALLBACK )
{
    msi_ending_callback = callback;
}
void msi_register_callback_recv_error ( MCALLBACK )
{
    msi_error_callback = callback;
}

/* Timeout */
void msi_register_callback_requ_timeout ( MCALLBACK )
{
    msi_timeout_callback = callback;
}
/* END REGISTERING */

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

/* Function for receiving and parsing a message that will be used internally */
msi_msg_t* receive_message ( msi_session_t* _session )
{
    assert(_session);


    msi_msg_t* _retu = _session->_oldest_msg;

    pthread_mutex_lock ( &_session->_mutex );

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    pthread_mutex_unlock ( &_session->_mutex );

    return _retu;
}

void msi_store_msg ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);
    assert(_msg);

    pthread_mutex_lock ( &_session->_mutex );

    if ( _session->_last_msg ) {
        _session->_last_msg->_next = _msg;
        _session->_last_msg = _msg;
    } else {
        _session->_last_msg = _session->_oldest_msg = _msg;
    }

    pthread_mutex_unlock ( &_session->_mutex );
}

int msi_send_msg ( msi_session_t* _session, msi_msg_t* _msg )
{
    int _status;

    if ( !_session->_call ) /* Which should never happen */
        return FAILURE;

    msi_msg_set_call_id ( _msg, _session->_call->_id );

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];
    t_memset ( _msg_string_final, '\0', MSI_MAXMSG_SIZE );

    _msg_string_final[0] = 69;

    uint8_t* _msg_string = msi_msg_to_string ( _msg );

    size_t _lenght = t_memlen ( _msg_string );

    memcpy ( _msg_string_final + 1, _msg_string, _lenght );

    _lenght += 1;

    _status = ( *msi_send_message_callback ) ( _session->_core_handler, _session->_friend_id, _msg_string_final, _lenght );

    free ( _msg_string );

    return _status;
}

/* Random stuff */
void flush_peer_type ( msi_session_t* _session, msi_msg_t* _msg, int _peer_id )
{
    if ( _msg->_call_type ) {
        if ( strcmp ( ( const char* ) _msg->_call_type->_header_value, CT_AUDIO_HEADER_VALUE ) == 0 ) {
            _session->_call->_type_peer[_peer_id] = type_audio;

        } else if ( strcmp ( ( const char* ) _msg->_call_type->_header_value, CT_VIDEO_HEADER_VALUE ) == 0 ) {
            _session->_call->_type_peer[_peer_id] = type_video;
        } else {} /* Error */
    } else {} /* Error */
}

int has_call_error ( msi_session_t* _session, msi_msg_t* _msg )
{
    msi_msg_t* _msg_error = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _error ) );

    if ( !_msg->_call_id ) {
        msi_msg_set_reason(_msg_error, stringify_error_code(error_no_callid) );

    } else if ( !_session->_call ) {
        msi_msg_set_reason(_msg_error, stringify_error_code(error_no_call) );

    } else if ( strcmp((const char*)_session->_call->_id, (const char*)_msg->_call_id->_header_value ) != 0 ) {
        msi_msg_set_reason(_msg_error, stringify_error_code(error_id_mismatch) );
    }

    if ( _msg_error->_reason ) {
        msi_send_msg ( _session, _msg_error );
        msi_free_msg ( _msg_error );
        return SUCCESS;
    }

    msi_free_msg ( _msg_error );
    return FAILURE;
}

/* --------- END OF GLOBAL FUNCTIONS USED BY THIS FILE --------- */

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

msi_session_t* msi_init_session ( void* _core_handler, const uint8_t* _user_agent )
{
    assert(_core_handler);
    assert(_user_agent);

    msi_session_t* _session = calloc ( sizeof ( msi_session_t ), 1 );
    assert(_session);

    _session->_oldest_msg = _session->_last_msg = NULL;
    _session->_core_handler = _core_handler;

    _session->_user_agent = t_strallcpy ( _user_agent );
    _session->_agent_handler = NULL;

    _session->_key = 0;
    _session->_call = NULL;

    _session->_frequ = 10000; /* default value? */
    _session->_call_timeout = 30000; /* default value? */

    /* Use the same frequency */
    _session->_event_handler = init_event_poll ( _session->_frequ );

    pthread_mutex_init ( &_session->_mutex, NULL );

    return _session;
}

int msi_terminate_session ( msi_session_t* _session )
{
    assert(_session);

    int _status = 0;

    terminate_event_poll ( _session->_event_handler );
    free ( _session );
    /* TODO: terminate the rest of the session */

    pthread_mutex_destroy ( &_session->_mutex );

    return _status;
}

msi_call_t* msi_init_call ( msi_session_t* _session, int _peers, uint32_t _timeoutms )
{
    assert(_session);
    assert(_peers);

    msi_call_t* _call = calloc ( sizeof ( msi_call_t ), 1 );
    _call->_type_peer = calloc ( sizeof ( call_type ), _peers );

    assert(_call);
    assert(_call->_type_peer);

    _call->_participants = _peers;
    _call->_key = _session->_key;
    _call->_timeoutst = _timeoutms;
    _call->_outgoing_timer_id = 0;

    return _call;
}

int msi_terminate_call ( msi_session_t* _session )
{
    assert(_session);

    if ( _session->_call->_type_peer )
        free ( _session->_call->_type_peer );

    cancel_timer_event(_session->_event_handler, _session->_call->_outgoing_timer_id);

    free ( _session->_call );

    _session->_call = NULL;

    return SUCCESS;
}
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

/* STATE HANDLERS */

/* REQUESTS */
int msi_handle_recv_invite ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( _session->_call ) {
        msi_msg_t* _msg_error = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _error ) );
        msi_msg_set_reason(_msg_error, stringify_error_code(error_busy));
        msi_send_msg(_session, _msg_error);
        msi_free_msg(_msg_error);

        return 0;
    }
    if ( !_msg->_call_id ) {
        msi_msg_t* _msg_error = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _error ) );
        msi_msg_set_reason(_msg_error, stringify_error_code(error_no_callid));
        msi_send_msg(_session, _msg_error);
        msi_free_msg(_msg_error);
        return 0;
    }

    _session->_call = msi_init_call ( _session, 1, _session->_call_timeout );
    t_memcpy(_session->_call->_id, _msg->_call_id->_header_value, _CALL_ID_LEN);
    _session->_call->_state = call_starting;

    flush_peer_type ( _session, _msg, 0 );

    msi_msg_t* _msg_ringing = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _ringing ) );
    msi_send_msg ( _session, _msg_ringing );
    msi_free_msg ( _msg_ringing );

    throw_event ( _session->_event_handler, msi_recv_invite_callback, _session );
    return 1;
}
int msi_handle_recv_start ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    _session->_call->_state = call_active;

    flush_peer_type ( _session, _msg, 0 );

    throw_event ( _session->_event_handler, msi_start_call_callback, _session );
    return 1;
}
int msi_handle_recv_reject ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    msi_msg_t* _msg_end = msi_msg_new ( TYPE_REQUEST, stringify_request ( _end ) );
    msi_send_msg ( _session, _msg_end );
    msi_free_msg ( _msg_end );

    throw_event ( _session->_event_handler, msi_reject_call_callback, _session );

    return 1;
}
int msi_handle_recv_cancel ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _ending ) );
    msi_send_msg ( _session, _msg_ending );
    msi_free_msg ( _msg_ending );

    msi_terminate_call ( _session );

    throw_event ( _session->_event_handler, msi_cancel_call_callback, _session );

    return 1;
}
int msi_handle_recv_end ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _ending ) );
    msi_send_msg ( _session, _msg_ending );
    msi_free_msg ( _msg_ending );

    msi_terminate_call ( _session );

    throw_event ( _session->_event_handler, msi_end_call_callback, _session );

    return 1;
}
/*--------*/

/* RESPONSES */
int msi_handle_recv_ringing ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    throw_event ( _session->_event_handler, msi_ringing_callback, _session );

    return 1;
}
int msi_handle_recv_starting ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    _session->_call->_state = call_active;

    msi_msg_t* _msg_start = msi_msg_new ( TYPE_REQUEST, stringify_request ( _start ) );
    msi_send_msg ( _session, _msg_start );
    msi_free_msg ( _msg_start );

    flush_peer_type ( _session, _msg, 0 );

    throw_event ( _session->_event_handler, msi_starting_callback, _session );
    cancel_timer_event(_session->_event_handler, _session->_call->_outgoing_timer_id);
    _session->_call->_outgoing_timer_id = 0;

    return 1;
}
int msi_handle_recv_ending ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);

    if ( has_call_error(_session, _msg) == 0 )
        return 0;

    msi_terminate_call ( _session );
    throw_event ( _session->_event_handler, msi_ending_callback, _session );

    return 1;
}
int msi_handle_recv_error ( msi_session_t* _session, msi_msg_t* _msg )
{
    assert(_session);
    assert(_session->_call);

    /* Handle error accordingly */
    if ( _msg->_reason ) {
        _session->_last_error_id = atoi((const char*)_msg->_reason->_header_value);
        _session->_last_error_str = stringify_error(_session->_last_error_id);
    }

    msi_terminate_call(_session);

    throw_event ( _session->_event_handler, msi_error_callback, _session );

    return 1;
}
/* ------------------ */

MCBTYPE msi_handle_timeout (void* _arg)
{
    msi_session_t* _session = _arg;
    msi_terminate_call(_session);

    (*msi_timeout_callback) (_arg);
    (*msi_ending_callback) (_arg);

}

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

int msi_invite ( msi_session_t* _session, call_type _call_type, uint32_t _timeoutms )
{
    assert(_session);

    if ( !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_invite = msi_msg_new ( TYPE_REQUEST, stringify_request ( _invite ) );

    _session->_call = msi_init_call ( _session, 1, _timeoutms ); /* Just one for now */
    msi_genterate_call_id(_session->_call->_id, _CALL_ID_LEN);
    _session->_call->_type_local = _call_type;
    /* Do whatever with message */

    if ( _call_type == type_audio ) {
        msi_msg_set_call_type ( _msg_invite, ( const uint8_t* ) CT_AUDIO_HEADER_VALUE );
    } else {
        msi_msg_set_call_type ( _msg_invite, ( const uint8_t* ) CT_VIDEO_HEADER_VALUE );
    }

    msi_send_msg ( _session, _msg_invite );
    msi_free_msg ( _msg_invite );

    _session->_call->_state = call_inviting;

    _session->_call->_outgoing_timer_id = throw_timer_event(_session->_event_handler, msi_handle_timeout, _session, _timeoutms );

    return 1;
}
int msi_hangup ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || ( !msi_send_message_callback && _session->_call->_state != call_active ) )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_REQUEST, stringify_request ( _end ) );
    msi_send_msg ( _session, _msg_ending );
    msi_free_msg ( _msg_ending );

    return 1;
}


int msi_answer ( msi_session_t* _session, call_type _call_type )
{
    assert(_session);

    if ( !msi_send_message_callback || !_session->_call )
        return 0;

    msi_msg_t* _msg_starting = msi_msg_new ( TYPE_RESPONSE, stringify_response ( _starting ) );
    _session->_call->_type_local = _call_type;

    if ( _call_type == type_audio ) {
        msi_msg_set_call_type ( _msg_starting, ( const uint8_t* ) CT_AUDIO_HEADER_VALUE );
    } else {
        msi_msg_set_call_type ( _msg_starting, ( const uint8_t* ) CT_VIDEO_HEADER_VALUE );
    }

    msi_send_msg ( _session, _msg_starting );
    msi_free_msg ( _msg_starting );

    _session->_call->_state = call_active;

    return 1;
}
int msi_cancel ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_cancel = msi_msg_new ( TYPE_REQUEST, stringify_request ( _cancel ) );
    msi_send_msg ( _session, _msg_cancel );
    msi_free_msg ( _msg_cancel );



    return 1;
}
int msi_reject ( msi_session_t* _session )
{
    assert(_session);

    if ( !_session->_call || !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_reject = msi_msg_new ( TYPE_REQUEST, stringify_request ( _reject ) );
    msi_send_msg ( _session, _msg_reject );
    msi_free_msg ( _msg_reject );

    return 1;
}

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

/* OUR MAIN POOL FUNCTION */
/*
 * Forks it self to other thread and then handles the session initiation.
 *
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


/*
 * Needs a bit more work on the protocol
 */
void* msi_poll_stack ( void* _session_p )
{
    msi_session_t* _session = ( msi_session_t* ) _session_p;
    msi_msg_t*     _msg = NULL;

    uint32_t* _frequ =  &_session->_frequ;
    while ( _session ) {

        /* At this point it's already parsed */
        _msg = receive_message ( _session );

        if ( _msg ) {

            if ( _msg->_request ) { /* Handle request */

                const uint8_t* _request_value = _msg->_request->_header_value;

                if ( same ( _request_value, stringify_request ( _invite ) ) ) {
                    msi_handle_recv_invite ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _start ) ) ) {
                    msi_handle_recv_start ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _cancel ) ) ) {
                    msi_handle_recv_cancel ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _reject ) ) ) {
                    msi_handle_recv_reject ( _session, _msg );

                } else if ( same ( _request_value, stringify_request ( _end ) ) ) {
                    msi_handle_recv_end ( _session, _msg );
                }

            } else if ( _msg->_response ) { /* Handle response */

                const uint8_t* _response_value = _msg->_response->_header_value;

                if ( same ( _response_value, stringify_response ( _ringing ) ) ) {
                    msi_handle_recv_ringing ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _starting ) ) ) {
                    msi_handle_recv_starting ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _ending ) ) ) {
                    msi_handle_recv_ending ( _session, _msg );

                } else if ( same ( _response_value, stringify_response ( _error ) ) ) {
                    msi_handle_recv_error ( _session, _msg );
                }

            }

            msi_free_msg ( _msg );

        }
        usleep ( *_frequ );
    }

    return NULL;
}

/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/
/*------------------------*/

/* Easy way to start the poll */

pthread_t msi_start_main_loop ( msi_session_t* _session, uint32_t _frequms )
{
    assert(_session);

    int _status;
    pthread_t _thread_id;


    _session->_frequ = _frequms * 1000;

    _status = pthread_create ( &_thread_id, NULL, msi_poll_stack, _session );

    if ( _status < 0 ) {
        printf ( "Error while starting main loop: %d, %s\n", errno, strerror ( errno ) );
        return _status;
    }

    _status = pthread_detach ( _thread_id );

    if ( _status < 0 ) {
        printf ( "Error while starting main loop: %d, %s\n", errno, strerror ( errno ) );
    }

    return _thread_id;
}
