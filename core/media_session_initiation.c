#include "media_session_initiation.h"
#include "net_crypto.h"
#include "Lossless_UDP.h"

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
int (*media_session_send_message_callback) ( int, uint8_t*, uint32_t ) = NULL;

int (*media_session_recv_invite_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_start_call_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_reject_call_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_cancel_call_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_end_call_callback) (STATE_CALLBACK_ARGS) = NULL;

int (*media_session_trying_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_ringing_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_starting_callback) (STATE_CALLBACK_ARGS) = NULL;
int (*media_session_ending_callback) (STATE_CALLBACK_ARGS) = NULL;
/* End of CALLBACKS */

/* REGISTER CALLBACKS */
void media_session_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) )
{
    media_session_send_message_callback = callback;
}

/* Function to be called when received invite.
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void media_session_register_callback_recv_invite(STATE_CALLBACK)
{
    media_session_recv_invite_callback = callback;
}

/* Function to be called when the call is started
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void media_session_register_callback_call_started(STATE_CALLBACK)
{
    media_session_start_call_callback = callback;
}

/* Function to be called when call is rejected
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void media_session_register_callback_call_rejected(STATE_CALLBACK)
{
    media_session_reject_call_callback = callback;
}

/* Function to be called when call is canceled
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void media_session_register_callback_call_canceled(STATE_CALLBACK)
{
    media_session_cancel_call_callback = callback;
}

void media_session_register_callback_call_ended(STATE_CALLBACK)
{
    media_session_cancel_call_callback = callback;
}


/* Functions to be called when gotten x response */
void media_session_register_callback_recv_trying(STATE_CALLBACK)
{
    media_session_trying_callback = callback;
}
void media_session_register_callback_recv_ringing(STATE_CALLBACK)
{
    media_session_ringing_callback = callback;
}
void media_session_register_callback_recv_starting(STATE_CALLBACK)
{
    media_session_starting_callback = callback;
}
void media_session_register_callback_recv_ending(STATE_CALLBACK)
{
    media_session_ending_callback = callback;
}

/* Function to be called when call is ended
 * This callback is all about what you do with it.
 * Everything else is done internally.
 */
void media_session_register_callback_call_end(STATE_CALLBACK)
{
    media_session_end_call_callback = callback;
}
/* END REGISTERING */

/* --------- END OF GLOBAL FUNCTIONS USED BY THIS FILE --------- */

media_session_t* media_init_session(IP_Port _to_dest)
{
    if ( _msession_handler )
        return _msession_handler;

    _msession_handler = malloc ( sizeof ( media_session_t ) );

    _msession_handler->_rtp_session = rtp_init_session(_to_dest, -1);

    return _msession_handler;
}

int media_terminate_session(media_session_t* _session)
{
    int status;

    if ( !_session )
        return -1;

    status = rtp_terminate_session(_session->_rtp_session);
    free(_session);

    /* Session termination etc... */

    return status;
}

/* STATE HANDLERS */

/* REQUESTS */
int media_session_handle_recv_invite( media_session_t* _session )
{
    media_msg_t* _msg = _session->_msg_list;

    media_msg_t* _msg_ringing = media_msg_new(TYPE_RESPONSE, _ringing );

    uint8_t* _msg_string = media_msg_to_string(_msg_ringing);
    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );
    free(_msg_string);

    free(_msg_ringing);

    if ( media_session_recv_invite_callback )
        (*media_session_recv_invite_callback) ();

    _session->_msg_list = _msg->next;
    _session->_last_request = _msg->_request;

    free(_msg); /* or else clear it */

    media_session_answer(_session); /* AUTO ANSWER */

    return 0;
}
int media_session_handle_recv_start( media_session_t* _session )
{
    media_msg_t* _msg = _session->_msg_list;

    if ( _session->_last_request == _invite && media_session_start_call_callback )
        (*media_session_start_call_callback) ();
    else {} /* Do some error */

    _session->_msg_list = _msg->next;
    _session->_last_request = _msg->_request;

    free(_msg); /* or else clear it */

    return 0;
}
int media_session_handle_recv_reject( media_session_t* _session )
{
    media_msg_t* _msg = _session->_msg_list;

    if ( _session->_last_request == _invite && media_session_reject_call_callback )
        (*media_session_reject_call_callback) ();
    else {} /* Do some error */

    _session->_last_request = _msg->_request;

    return 0;
}
int media_session_handle_recv_cancel( media_session_t* _session )
{
    media_msg_t* _msg = _session->_msg_list;

    if ( _session->_last_request == _invite && media_session_cancel_call_callback )
        (*media_session_cancel_call_callback) ();
    else {} /* Do some error */

    _session->_last_request = _msg->_request;

    return 0;
}
int media_session_handle_recv_end( media_session_t* _session )
{
    media_msg_t* _msg = _session->_msg_list;

    if ( _session->_last_request == _invite && media_session_end_call_callback )
        (*media_session_end_call_callback) ();
    else {} /* Do some error */

    _session->_last_request = _msg->_request;

    media_msg_t* _msg_ringing = media_msg_new(TYPE_RESPONSE, _ending );

    uint8_t* _msg_string = media_msg_to_string(_msg_ringing);
    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );
    free(_msg_string);

    return 0;
}
/*--------*/
/* RESPONSES */
int media_session_handle_recv_trying ( media_session_t* _session )
{
    /* Still not implemented nor do i think it needs to be */
    (*media_session_trying_callback)();
    return 0;
}
int media_session_handle_recv_ringing ( media_session_t* _session )
{
    (*media_session_ringing_callback)();
    _session->_last_response = _ringing;
    return 0;
}
int media_session_handle_recv_starting ( media_session_t* _session )
{
    if ( !media_session_send_message_callback )
        return 0;

    (*media_session_starting_callback)();
    _session->_last_response = _starting;

     media_msg_t* _msg_start = media_msg_new( TYPE_REQUEST, _starting );

    /* Do whatever with message */

    uint8_t* _msg_string = media_msg_to_string(_msg_start);
    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );
    free(_msg_string);
    free(_msg_start);

    return 0;
}
int media_session_handle_recv_ending ( media_session_t* _session )
{
    (*media_session_ending_callback)();
    _session->_last_response = _ending;
    return 0;
}
/* ------------------ */

int media_session_invite ( media_session_t* _session )
{
    if ( !media_session_send_message_callback )
        return 0;

    media_msg_t* _msg_invite = media_msg_new(TYPE_REQUEST, _invite);

    /* Do whatever with message */

    uint8_t* _msg_string = media_msg_to_string(_msg_invite);

    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );

    return 1;
}
int media_session_answer ( media_session_t* _session )
{
    if ( !media_session_send_message_callback && _session->_last_request != _invite )
        return 0;

    media_msg_t* _msg_starting = media_msg_new( TYPE_RESPONSE, _starting );

    /* Do whatever with message */

    uint8_t* _msg_string = media_msg_to_string(_msg_starting);
    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );
    free(_msg_string);
    free(_msg_starting);

    _session->_call_info = call_active;

    return 1;
}
int media_session_hangup( media_session_t* _session )
{
    if ( !media_session_send_message_callback && _session->_call_info != call_active )
        return 0;

    media_msg_t* _msg_starting = media_msg_new( TYPE_RESPONSE, _starting );

    /* Do whatever with message */

    uint8_t* _msg_string = media_msg_to_string(_msg_starting);
    (*media_session_send_message_callback)(_session->_friend_id, _msg_string, m_strlen(_msg_string) );
    free(_msg_string);
    free(_msg_starting);


    _session->_call_info = call_ended;

    return 1;
}

void* media_session_pool_stack(void* _session_p)
{
    if ( !media_session_send_message_callback )
        return NULL;

    media_session_t* _session = (media_session_t*) _session_p;

    while ( _session ) /* main loop */
    {
        if ( _session->_msg_list ){

            if ( _session->_msg_list->_request != _no_request ){ /* Handle request */

                switch ( _session->_msg_list->_request ){
                case _invite:
                    media_session_handle_recv_invite(_session);
                    break;
                case _start:
                    media_session_handle_recv_start(_session);
                    break;
                case _cancel:
                    media_session_handle_recv_cancel(_session);
                    break;
                case _reject:
                    media_session_handle_recv_reject(_session);
                    break;
                case _end:
                    media_session_handle_recv_end(_session);
                    break;
                case _no_request:
                    /* ERROR */
                    break;
                default:
                    break;
                }

            } else if ( _session->_msg_list->_response != _no_response ){ /* Handle response */

                switch ( _session->_msg_list->_response ){
                case _trying:
                    media_session_handle_recv_trying(_session);
                    break;
                case _ringing:
                    media_session_handle_recv_ringing(_session);
                    break;
                case _starting:
                    media_session_handle_recv_starting(_session);
                    break;
                case _ending:
                    media_session_handle_recv_ending(_session);
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
        usleep(10000); /* 10 ms is pretty fine */
    }

    return NULL;
}
