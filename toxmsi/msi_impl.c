#include "msi_impl.h"
#include "msi_message.h"

#include <assert.h>

size_t m_strlen ( uint8_t* _str )
{
    uint8_t* _it = _str;

    size_t _count;
    for ( _count = 0; *_it != '\0'; ++_it ) { _count ++; }

    return _count + 1;
}


static media_session_t* _msession_handler = NULL;
/* The same pointer handled through a session.
 * This could be changed depending on a amount of sessions
 * required.
 */

/* --------- GLOBAL FUNCTIONS USED BY THIS FILE --------- */

/* CALLBACKS */
/*int (*msi_send_message_callback) ( int, uint8_t*, uint32_t ) = NULL;*/
int ( *msi_send_message_callback ) ( int _socket, tox_IP_Port,  uint8_t*, uint32_t ) = NULL;
int ( *msi_recv_message_callback ) ( tox_IP_Port*, uint8_t*, uint32_t* ) = NULL;

int ( *msi_recv_invite_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_start_call_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_reject_call_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_cancel_call_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_end_call_callback ) ( STATE_CALLBACK_ARGS ) = NULL;

int ( *msi_trying_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_ringing_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_starting_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
int ( *msi_ending_callback ) ( STATE_CALLBACK_ARGS ) = NULL;
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
void msi_register_callback_send ( int ( *callback ) ( int _socket, tox_IP_Port, uint8_t*, uint32_t ) )
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
void msi_register_callback_recv_invite ( STATE_CALLBACK )
{
    msi_recv_invite_callback = callback;
}

/* Function to be called when the call is started
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_started ( STATE_CALLBACK )
{
    msi_start_call_callback = callback;
}

/* Function to be called when call is rejected
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_rejected ( STATE_CALLBACK )
{
    msi_reject_call_callback = callback;
}

/* Function to be called when call is canceled
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_canceled ( STATE_CALLBACK )
{
    msi_cancel_call_callback = callback;
}

void msi_register_callback_call_ended ( STATE_CALLBACK )
{
    msi_end_call_callback = callback;
}


/* Functions to be called when gotten x response */
void msi_register_callback_recv_trying ( STATE_CALLBACK )
{
    msi_trying_callback = callback;
}
void msi_register_callback_recv_ringing ( STATE_CALLBACK )
{
    msi_ringing_callback = callback;
}
void msi_register_callback_recv_starting ( STATE_CALLBACK )
{
    msi_starting_callback = callback;
}
void msi_register_callback_recv_ending ( STATE_CALLBACK )
{
    msi_ending_callback = callback;
}

/* Function to be called when call is ended
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void msi_register_callback_call_end ( STATE_CALLBACK )
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
media_msg_t* receive_message ( media_session_t* _session )
{
    media_msg_t* _retu = _session->_oldest_msg;

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    return _retu;
}

int send_msg ( media_session_t* _session, media_msg_t* _msg )
{
    int _status;

    uint8_t _msg_string_final [1024]; /* For testing purposes */
    _msg_string_final[0] = 69;

    uint8_t* _msg_string = msi_msg_to_string ( _msg );

    size_t _lenght = m_strlen ( _msg_string );

    memcpy ( _msg_string_final + 1, _msg_string, _lenght );

    _lenght += 1;

    _status = ( *msi_send_message_callback ) ( _session->_socket, _session->_friend_id, _msg_string_final, _lenght );
    free ( _msg_string );

    return _status;
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

media_session_t* msi_init_session ( int _socket )
{
    if ( _msession_handler )
        return _msession_handler;

    _msession_handler = malloc ( sizeof ( media_session_t ) );

    _msession_handler->_rtp_audio = NULL;
    _msession_handler->_rtp_video = NULL;

    _msession_handler->_oldest_msg = _msession_handler->_last_msg = NULL;
    _msession_handler->_call_info = -1;
    _msession_handler->_socket = _socket;

    return _msession_handler;
}

int msi_terminate_session ( media_session_t* _session )
{
    int _status = 0;

    if ( !_session )
        return -1;

    if ( _session->_rtp_audio )
        _status = rtp_terminate_session ( _session->_rtp_audio );

    if ( _session->_rtp_video )
        _status = rtp_terminate_session ( _session->_rtp_video );

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
int msi_handle_recv_invite ( media_session_t* _session, media_msg_t* _msg )
{
    /* media_msg_t* _msg = _session->_msg_list_head; */

    media_msg_t* _msg_ringing = msi_msg_new ( TYPE_RESPONSE, _ringing );

    _session->_friend_id = _msg->_friend_id;

    send_msg ( _session, _msg_ringing );

    free ( _msg_ringing );


    /* _session->_msg_list_head = _msg->next; */
    _session->_last_request = _msg->_request;

    _session->_call_info = call_inviting;

    free ( _msg ); /* or else clear it */

    if ( !msi_recv_invite_callback )
        return 0;

    return ( *msi_recv_invite_callback ) ();
}
int msi_handle_recv_start ( media_session_t* _session, media_msg_t* _msg )
{
    /* media_msg_t* _msg = _session->_msg_list_head; */

    _session->_friend_id = _msg->_friend_id;

    if ( _session->_last_request != _invite || !msi_start_call_callback )
        return 0;

    /* _session->_msg_list_head = _msg->next; */
    _session->_last_request = _msg->_request;

    return ( *msi_start_call_callback ) ();
}
int msi_handle_recv_reject ( media_session_t* _session, media_msg_t* _msg )
{
    /* media_msg_t* _msg = _session->_msg_list_head; */

    _session->_friend_id = _msg->_friend_id;

    if ( !msi_reject_call_callback )
        return 0;

    _session->_last_request = _msg->_request;

    media_msg_t* _msg_ending = msi_msg_new ( TYPE_REQUEST, _end );

    /* Do whatever with message */

    send_msg ( _session, _msg_ending );

    free ( _msg_ending );

    return ( *msi_reject_call_callback ) ();
}
int msi_handle_recv_cancel ( media_session_t* _session, media_msg_t* _msg )
{
    /* media_msg_t* _msg = _session->_msg_list_head; */

    _session->_friend_id = _msg->_friend_id;

    if ( _session->_last_request != _invite || !msi_cancel_call_callback )
        return 0;

    _session->_last_request = _msg->_request;

    return ( *msi_cancel_call_callback ) ();
}
int msi_handle_recv_end ( media_session_t* _session, media_msg_t* _msg )
{
    /* media_msg_t* _msg = _session->_msg_list_head; */

    _session->_friend_id = _msg->_friend_id;

    if ( !msi_end_call_callback )
        return 0;

    _session->_last_request = _msg->_request;

    media_msg_t* _msg_ending = msi_msg_new ( TYPE_RESPONSE, _ending );

    send_msg ( _session, _msg_ending );

    free ( _msg_ending );

    _session->_call_info = call_ended;

    return ( *msi_end_call_callback ) ();
}
/*--------*/

/* RESPONSES */
int msi_handle_recv_trying ( media_session_t* _session )
{
    if ( !msi_trying_callback )
        return 0;
    /* Still not implemented nor do i think it needs to be */
    return ( *msi_trying_callback ) ();
}
int msi_handle_recv_ringing ( media_session_t* _session )
{
    _session->_last_response = _ringing;

    if ( !msi_ringing_callback )
        return 0;

    return ( *msi_ringing_callback ) ();
}
int msi_handle_recv_starting ( media_session_t* _session )
{
    _session->_last_response = _starting;

    if ( !msi_send_message_callback || !msi_starting_callback )
        return 0;

    media_msg_t* _msg_start = msi_msg_new ( TYPE_REQUEST, _start );

    /* Do whatever with message */

    send_msg ( _session, _msg_start );

    free ( _msg_start );

    _session->_call_info = call_active;

    return ( *msi_starting_callback ) ();
}
int msi_handle_recv_ending ( media_session_t* _session )
{
    if ( !msi_starting_callback )
        return 0;

    _session->_last_response = _ending;

    _session->_call_info = call_ended;

    return ( *msi_ending_callback ) ();
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

int msi_invite ( media_session_t* _session )
{
    if ( !msi_send_message_callback )
        return 0;

    media_msg_t* _msg_invite = msi_msg_new ( TYPE_REQUEST, _invite );

    /* Do whatever with message */

    send_msg ( _session, _msg_invite );

    free ( _msg_invite );

    _session->_call_info = call_inviting;

    return 1;
}
int msi_hangup ( media_session_t* _session )
{
    if ( !msi_send_message_callback && _session->_call_info != call_active )
        return 0;

    media_msg_t* _msg_ending = msi_msg_new ( TYPE_REQUEST, _end );

    /* Do whatever with message */

    send_msg ( _session, _msg_ending );

    free ( _msg_ending );

    return 1;
}


int msi_answer ( media_session_t* _session )
{
    if ( !msi_send_message_callback && _session->_last_request != _invite )
        return 0;

    media_msg_t* _msg_starting = msi_msg_new ( TYPE_RESPONSE, _starting );

    /* Do whatever with message */

    send_msg ( _session, _msg_starting );

    free ( _msg_starting );

    _session->_call_info = call_active;

    return 1;
}
int msi_cancel ( media_session_t* _session )
{
    if ( !msi_send_message_callback )
        return 0;

    media_msg_t* _msg_cancel = msi_msg_new ( TYPE_REQUEST, _cancel );

    send_msg ( _session, _msg_cancel );

    free ( _msg_cancel );

    return 1;
}
int msi_reject ( media_session_t* _session )
{
    if ( !msi_send_message_callback )
        return 0;

    media_msg_t* _msg_reject = msi_msg_new ( TYPE_REQUEST, _reject );

    send_msg ( _session, _msg_reject );

    free ( _msg_reject );

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

void* msi_poll_stack ( void* _session_p )
{
    media_session_t* _session = ( media_session_t* ) _session_p;
    media_msg_t*     _msg = NULL;

    while ( _session ) { /* main loop */
        _msg = receive_message ( _session );

        if ( _msg ) {

            if ( _msg->_request != _no_request ) { /* Handle request */

                switch ( _msg->_request ) {
                case _invite:
                    msi_handle_recv_invite ( _session, _msg );
                    break;
                case _start:
                    msi_handle_recv_start ( _session, _msg );
                    break;
                case _cancel:
                    msi_handle_recv_cancel ( _session, _msg );
                    break;
                case _reject:
                    msi_handle_recv_reject ( _session, _msg );
                    break;
                case _end:
                    msi_handle_recv_end ( _session, _msg );
                    break;
                case _no_request:
                    /* ERROR */
                    break;
                default:
                    break;
                }

            } else if ( _msg->_response != _no_response ) { /* Handle response */

                switch ( _msg->_response ) {
                case _trying:
                    msi_handle_recv_trying ( _session );
                    break;
                case _ringing:
                    msi_handle_recv_ringing ( _session );
                    break;
                case _starting:
                    msi_handle_recv_starting ( _session );
                    break;
                case _ending:
                    msi_handle_recv_ending ( _session );
                    break;
                case _no_response:
                    /* ERROR */
                    break;
                default:
                    break;
                }

            } else { /* Error delete and call msg_error_callback */

            }

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

int msi_start_main_loop ( media_session_t* _session )
{
    int _status;

    if ( !_session )
        return -1;

    _status = pthread_create ( &_session->_thread_id, NULL, msi_poll_stack, ( void* ) _session );

    if ( _status < 0 ) {
        printf ( "Error while starting main loop: %d, %s\n", errno, strerror ( errno ) );
        return _status;
    }

    _status = pthread_detach ( _session->_thread_id );

    if ( _status < 0 ) {
        printf ( "Error while starting main loop: %d, %s\n", errno, strerror ( errno ) );
    }

    return _status;
}
