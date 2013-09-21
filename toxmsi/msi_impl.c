#define _BSD_SOURCE

#include "msi_impl.h"
#include "msi_message.h"
#include "../toxrtp/rtp_helper.h"

#include <assert.h>
#include <unistd.h>
#include <string.h>

#define same(x, y) strcmp((const char*) x, (const char*) y) == 0

static msi_session_t* _msession_handler = NULL;
/* The same pointer handled through a session.
 * This could be changed depending on a amount of sessions
 * required.
 */

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

MCBTYPE ( *msi_trying_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_ringing_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_starting_callback ) ( MCBARGS ) = NULL;
MCBTYPE ( *msi_ending_callback ) ( MCBARGS ) = NULL;
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
void msi_register_callback_recv_trying ( MCALLBACK )
{
    msi_trying_callback = callback;
}
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

/* Function to be called when call is ended
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_end ( MCALLBACK )
{
    msi_end_call_callback = callback;
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
    msi_msg_t* _retu = _session->_oldest_msg;

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    return _retu;
}

int msi_send_msg ( msi_session_t* _session, msi_msg_t* _msg )
{
    int _status;

    uint8_t _msg_string_final [MSI_MAXMSG_SIZE];
    t_memset(_msg_string_final, '\0', MSI_MAXMSG_SIZE);

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
void flush_session_type ( msi_session_t* _session, msi_msg_t* _msg )
{
    if ( _msg->_call_type ){
        if ( strcmp( (const char*) _msg->_call_type->_header_value, CT_AUDIO_HEADER_VALUE ) == 0 ){
            _session->_peer_call_type = type_audio;

        } else if ( strcmp( (const char*) _msg->_call_type->_header_value, CT_VIDEO_HEADER_VALUE ) == 0 ){
            _session->_peer_call_type = type_video;
        } else {} /* Error */
    } else {} /* Error */
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
    if ( _msession_handler ) /* Only one session possible for now? */
        return _msession_handler;

    msi_session_t* _session = _msession_handler = malloc ( sizeof ( msi_session_t ) );

    _session->_oldest_msg = _session->_last_msg = NULL;
    _session->_call_info = call_inactive;
    _session->_core_handler = _core_handler;

    _session->_local_call_type = type_audio;
    _session->_peer_call_type  = type_audio;

    _session->_user_agent = t_strallcpy(_user_agent);
    _session->_agent_handler = NULL;

    return _session;
}

int msi_terminate_session ( msi_session_t* _session )
{
    int _status = 0;

    if ( !_session )
        return -1;

    free ( _session );

    /* Session termination etc... */

    return _status;
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
    _session->_last_request = _invite;

    msi_msg_t* _msg_ringing = msi_msg_new ( TYPE_RESPONSE, stringify_response(_ringing) );
    msi_send_msg ( _session, _msg_ringing );
    msi_free_msg(_msg_ringing);

    _session->_call_info = call_starting;
    flush_session_type(_session, _msg);

    if ( !msi_recv_invite_callback )
        return 0;

    return ( *msi_recv_invite_callback ) (_session);
}
int msi_handle_recv_start ( msi_session_t* _session, msi_msg_t* _msg )
{
    _session->_last_request = _start;
    _session->_call_info = call_active;

    if ( !msi_start_call_callback )
        return 0;

    flush_session_type(_session, _msg);

    return ( *msi_start_call_callback ) (_session);
}
int msi_handle_recv_reject ( msi_session_t* _session, msi_msg_t* _msg )
{
    _session->_last_request = _reject;

    if ( !msi_reject_call_callback )
        return 0;

    msi_msg_t* _msg_end = msi_msg_new ( TYPE_REQUEST, stringify_request(_end) );
    msi_send_msg ( _session, _msg_end );
    msi_free_msg ( _msg_end );

    _session->_call_info = call_inactive;

    return ( *msi_reject_call_callback ) (_session);
}
int msi_handle_recv_cancel ( msi_session_t* _session, msi_msg_t* _msg )
{
    _session->_last_request = _cancel;

    if ( _session->_last_request != _invite || !msi_cancel_call_callback )
        return 0;

    return ( *msi_cancel_call_callback ) (_session);
}
int msi_handle_recv_end ( msi_session_t* _session, msi_msg_t* _msg )
{
    _session->_last_request = _end;

    if ( !msi_end_call_callback )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_RESPONSE, stringify_response(_ending) );
    msi_send_msg ( _session, _msg_ending );
    msi_free_msg ( _msg_ending );

    _session->_call_info = call_inactive;

    return ( *msi_end_call_callback ) (_session);
}
/*--------*/

/* RESPONSES */
int msi_handle_recv_trying ( msi_session_t* _session )
{
    _session->_last_response = _trying;

    if ( !msi_trying_callback )
        return 0;

    return ( *msi_trying_callback ) (_session);
}
int msi_handle_recv_ringing ( msi_session_t* _session )
{
    _session->_last_response = _ringing;

    if ( !msi_ringing_callback )
        return 0;

    return ( *msi_ringing_callback ) (_session);
}
int msi_handle_recv_starting ( msi_session_t* _session, msi_msg_t* _msg )
{
    _session->_last_response = _starting;
    _session->_call_info = call_active;

    if ( !msi_send_message_callback || !msi_starting_callback )
        return 0;

    msi_msg_t* _msg_start = msi_msg_new ( TYPE_REQUEST, stringify_request(_start) );
    msi_send_msg ( _session, _msg_start );
    msi_free_msg ( _msg_start );

    flush_session_type(_session, _msg);

    return ( *msi_starting_callback ) (_session);
}
int msi_handle_recv_ending ( msi_session_t* _session )
{
    if ( !msi_ending_callback )
        return 0;

    _session->_last_response = _ending;
    _session->_call_info = call_inactive;

    return ( *msi_ending_callback ) (_session);
}
/* ------------------ */

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

int msi_invite ( msi_session_t* _session, call_type _call_type )
{
    if ( !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_invite = msi_msg_new ( TYPE_REQUEST, stringify_request(_invite) );
    _session->_local_call_type = _call_type;
    /* Do whatever with message */

    if ( _call_type == type_audio){
        msi_msg_set_call_type(_msg_invite, (const uint8_t*)CT_AUDIO_HEADER_VALUE );
    } else {
        msi_msg_set_call_type(_msg_invite, (const uint8_t*)CT_VIDEO_HEADER_VALUE );
    }

    msi_send_msg ( _session, _msg_invite );
    msi_free_msg ( _msg_invite );

    _session->_call_info = call_inviting;

    return 1;
}
int msi_hangup ( msi_session_t* _session )
{
    _session->_call_info = call_inactive;

    if ( !msi_send_message_callback && _session->_call_info != call_active )
        return 0;

    msi_msg_t* _msg_ending = msi_msg_new ( TYPE_REQUEST, stringify_request(_end) );
    msi_send_msg ( _session, _msg_ending );
    msi_free_msg ( _msg_ending );

    return 1;
}


int msi_answer ( msi_session_t* _session, call_type _call_type )
{
    if ( !msi_send_message_callback && _session->_last_request != _invite )
        return 0;

    msi_msg_t* _msg_starting = msi_msg_new ( TYPE_RESPONSE, stringify_response(_starting) );
    _session->_local_call_type = _call_type;

    if( _call_type == type_audio ){
        msi_msg_set_call_type( _msg_starting, (const uint8_t*)CT_AUDIO_HEADER_VALUE );
    } else {
        msi_msg_set_call_type( _msg_starting, (const uint8_t*)CT_VIDEO_HEADER_VALUE );
    }

    msi_send_msg ( _session, _msg_starting );
    msi_free_msg ( _msg_starting );

    _session->_call_info = call_active;

    return 1;
}
int msi_cancel ( msi_session_t* _session )
{
    if ( !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_cancel = msi_msg_new ( TYPE_REQUEST, stringify_request(_cancel) );
    msi_send_msg ( _session, _msg_cancel );
    msi_free_msg ( _msg_cancel );

    return 1;
}
int msi_reject ( msi_session_t* _session )
{
    if ( !msi_send_message_callback )
        return 0;

    msi_msg_t* _msg_reject = msi_msg_new ( TYPE_REQUEST, stringify_request(_reject) );
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
    msi_msg_t*       _msg = NULL;

    while ( _session ) { /* main loop */

        /* At this point it's already parsed */
        _msg = receive_message ( _session );

        if ( _msg ) {

            if ( _msg->_request ) { /* Handle request */

                const uint8_t* _request_value = _msg->_request->_header_value;

                if          ( same(_request_value, stringify_request(_invite)) ) {
                    msi_handle_recv_invite ( _session, _msg );

                } else if   ( same(_request_value, stringify_request(_start))) {
                    msi_handle_recv_start ( _session, _msg );

                } else if   ( same(_request_value, stringify_request(_cancel))) {
                    msi_handle_recv_cancel ( _session, _msg );

                } else if   ( same(_request_value, stringify_request(_reject))) {
                    msi_handle_recv_reject ( _session, _msg );

                } else if   ( same(_request_value, stringify_request(_end))) {
                    msi_handle_recv_end ( _session, _msg );
                }

            } else if ( _msg->_response ) { /* Handle response */

                const uint8_t* _response_value = _msg->_response->_header_value;

                if          ( same(_response_value, stringify_response(_trying)) ) {
                    msi_handle_recv_trying ( _session );

                } else if   ( same(_response_value, stringify_response(_ringing))) {
                    msi_handle_recv_ringing ( _session );

                } else if   ( same(_response_value, stringify_response(_starting))) {
                    msi_handle_recv_starting ( _session, _msg );

                } else if   ( same(_response_value, stringify_response(_ending))) {
                    msi_handle_recv_ending ( _session );
                }

            }

            msi_free_msg(_msg);

        }
        usleep ( 10000 ); /* 10 ms is pretty fine */
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

pthread_t msi_start_main_loop ( msi_session_t* _session )
{
    int _status;
    pthread_t _thread_id;

    if ( !_session )
        return 0;

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
