#include "msi_impl.h"
#include "msi_message.h"
#include "rtp_message.h"
#include "toxrtp/tests/test_helper.h"
#include <curses.h>
#include <assert.h>


static media_session_t* _m_session = NULL; /* for the sake of test */

pthread_mutex_t _mutex;

static int _socket;

/* My recv functions */
int rtp_handlepacket ( rtp_session_t* _session, uint8_t* data, uint32_t length )
{
    rtp_msg_t* _msg = rtp_msg_parse ( _session, data, length );

    if ( !_msg )
        return FAILURE;


    if ( _session->_last_msg ) {
        _session->_last_msg->_next = _msg;
        _session->_last_msg = _msg;
    } else {
        _session->_last_msg = _session->_oldest_msg = _msg;
    }


    return SUCCESS;
}
int msi_handlepacket ( media_session_t* _session, tox_IP_Port ip_port, uint8_t* data, uint32_t length )
{
    media_msg_t* _msg;
    _msg = msi_parse_msg ( 0, data, length );

    if ( _msg ) {
        _msg->_friend_id = ip_port;
    } else {
        return FAILURE;
    }

    if ( _session->_last_msg ) {
        _session->_last_msg->_next = _msg;
        _session->_last_msg = _msg;
    } else {
        _session->_last_msg = _session->_oldest_msg = _msg;
    }

    return SUCCESS;
}
void* phone_receivepacket ( void* _session_p )
{
    media_session_t* _session = _session_p;

    uint32_t  _bytes;
    tox_IP_Port   _from;
    uint8_t _socket_data[MAX_UDP_PACKET_SIZE];

    int _m_socket = _socket;

    while ( _session ) {

        int _status = receivepacket ( _m_socket, &_from, _socket_data, &_bytes );

        if ( _status == FAILURE )  /* nothing recved */
            continue;

        pthread_mutex_lock ( &_mutex );
        switch ( _socket_data[0] ) {
        case MSI_PACKET:
            msi_handlepacket ( _session, _from, _socket_data + 1, _bytes );
            break;
        case RTP_PACKET:
            if ( _session->_rtp_session )
                rtp_handlepacket ( _session->_rtp_session, _socket_data + _session->_rtp_session->_prefix_length, _bytes );
            break;
        default:
            break;
        };
        pthread_mutex_unlock ( &_mutex );

    }
    pthread_exit ( NULL );
}

/* ---------------- */

/* My answering callback */
static pthread_t _handle_receive_tid = 0;
static pthread_t _handle_call_tid = 0;

void* handle_receive_callback ( void* _p )
{
    int _status;

    _p = NULL;

    char _choice [10];

    do {
        gets ( _choice );
        if ( strcmp ( _choice, "a" ) == 0 ) {
            printf ( "Answering...\n" );
            _status = msi_answer ( _m_session );
            break;
        } else if ( strcmp ( _choice, "r" ) == 0 ) {
            printf ( "Rejecting...\n" );
            _status = msi_reject ( _m_session );
            break;
        }

    } while ( strcmp ( _choice, "c" ) == 0 );

    _handle_receive_tid = 0;

    pthread_exit ( &_status );
}

/* Media transport callback */
typedef struct hmtc_args_s {
    rtp_session_t* _rtp_session;
    int* _thread_running;
} hmtc_args_t;

void* handle_media_transport_callback ( void* _hmtc_args_p )
{
    rtp_msg_t* _msg;

    hmtc_args_t* _hmtc_args = _hmtc_args_p;

    rtp_session_t* _rtp_session = _hmtc_args->_rtp_session;
    int* _thread_running = _hmtc_args->_thread_running;

    int _m_socket = _socket;

    while ( *_thread_running == 1 ) {
        /*
         * This part checks for received messages and if gotten one
         * display 'Received msg!' indicator and free message
         */
        _msg = rtp_recv_msg ( _rtp_session );

        if ( _msg ) {
            /* Do whatever with msg */
            rtp_free_msg ( _rtp_session, _msg );
        }
        /* -------------------- */

        /*
         * This one makes a test msg and sends that message to the 'remote'
         */
        _msg = rtp_msg_new ( _rtp_session, "abcd", 4 ) ;
        rtp_send_msg ( _rtp_session, _msg, _m_socket );
        usleep ( 10000 );
        /* -------------------- */
    }

    _thread_running = -1;

    pthread_exit ( NULL );
}

/* This is call control callback */
void* handle_call_callback ( void* _p )
{
    int _status;

    pthread_t _rtp_tid;
    int _rtp_thread_running = 1;
    rtp_session_t* _rtp_session = _m_session->_rtp_session = rtp_init_session ( -1 );

    rtp_add_receiver ( _rtp_session, &_m_session->_friend_id );
    uint8_t _prefix = RTP_PACKET;
    rtp_set_prefix ( _rtp_session, &_prefix, 1 );

    hmtc_args_t rtp_targs = { _rtp_session, &_rtp_thread_running };

    _status = pthread_create ( &_rtp_tid, NULL, handle_media_transport_callback, &rtp_targs );

    if ( _status < 0 ) {
        printf ( "Error while starting media transport: %d, %s\n", errno, strerror ( errno ) );
        return _status;
    }

    _status = pthread_detach ( _rtp_tid );

    if ( _status < 0 ) {
        printf ( "Error while starting media transport: %d, %s\n", errno, strerror ( errno ) );
        return _status;
    }

    _p = NULL;

    char _choice [10];

    /* Start media transport thread */

    do {
        gets ( _choice );
        if ( strcmp ( _choice, "h" ) == 0 ) {
            printf ( "Hanging up...\n" );
            _status = msi_hangup ( _m_session );
            break;
        }

    } while ( strcmp ( _choice, "c" ) == 0 );

    _handle_call_tid = 0;

    _rtp_thread_running = 0;

    while ( _rtp_thread_running != -1 );

    pthread_exit ( &_status );
}


/* Some example callbacks */

int callback_recv_invite ( STATE_CALLBACK_ARGS )
{
    int _status = SUCCESS;

    printf ( "Incomming call! \n" );
    printf ( "Options: a-(answer) r-(reject ) \n" );

    if ( _handle_receive_tid == 0 ) {
        _status = pthread_create ( &_handle_receive_tid, NULL, handle_receive_callback, NULL );

        if ( _status < 0 ) {
            printf ( "Error while starting receive call: %d, %s\n", errno, strerror ( errno ) );
            return _status;
        }

        _status = pthread_detach ( _handle_receive_tid );

        if ( _status < 0 ) {
            printf ( "Error while starting receive call: %d, %s\n", errno, strerror ( errno ) );
        }
    } else {
        /* Reject */
        return FAILURE;
    }

    return _status;
}
int callback_recv_trying ( STATE_CALLBACK_ARGS )
{
    printf ( "Trying...\n" );
    return SUCCESS;
}
int callback_recv_ringing ( STATE_CALLBACK_ARGS )
{
    printf ( "Ringing...\n" );
    return SUCCESS;
}
int callback_recv_starting ( STATE_CALLBACK_ARGS )
{
    int _status = SUCCESS;

    printf ( "Call started... ( press h to hangup ) \n" );

    if ( _handle_call_tid == 0 ) {
        _status = pthread_create ( &_handle_call_tid, NULL, handle_call_callback, NULL );

        if ( _status < 0 ) {
            printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
            return _status;
        }

        _status = pthread_detach ( _handle_call_tid );

        if ( _status < 0 ) {
            printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        }
    } else {
        /* Reject */
        return FAILURE;
    }

    return SUCCESS;
}
int callback_recv_ending ( STATE_CALLBACK_ARGS )
{
    printf ( "Call ended! (exiting)\n" );
    pthread_mutex_destroy ( &_mutex );
    exit ( SUCCESS );
    return SUCCESS;
}


int callback_call_started ( STATE_CALLBACK_ARGS )
{
    int _status = SUCCESS;

    printf ( "Call started... ( press h to hangup ) \n" );

    if ( _handle_call_tid == 0 ) {
        _status = pthread_create ( &_handle_call_tid, NULL, handle_call_callback, NULL );

        if ( _status < 0 ) {
            printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
            return _status;
        }

        _status = pthread_detach ( _handle_call_tid );

        if ( _status < 0 ) {
            printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        }
    } else {
        /* Reject */
        return FAILURE;
    }

    return SUCCESS;
}
int callback_call_canceled ( STATE_CALLBACK_ARGS )
{
    printf ( "On call canceled!\n" );
    return SUCCESS;
}
int callback_call_rejected ( STATE_CALLBACK_ARGS )
{
    printf ( "Call rejected!\n" );
    return SUCCESS;
}
int callback_call_ended ( STATE_CALLBACK_ARGS )
{
    printf ( "On call ended (exiting)!\n" );
    pthread_mutex_destroy ( &_mutex );
    exit ( SUCCESS );
    return SUCCESS;
}

/* ---------------------- */

int print_help ( const char* _name )
{
    printf ( "Usage: %s -m [ r/s ( mode ) ] [ -d ( destination IP ) ] \n", _name );
    return FAILURE;
}

int main ( int argc, char* argv [] )
{
    int _status;
    unsigned short _send_port, _recv_port;

    pthread_mutex_init ( &_mutex, NULL );

    arg_t* _args = parse_args ( argc, argv );

    const char* _mode = find_arg_duble ( _args, "-m" );
    const char* _ip   = find_arg_duble ( _args, "-d" );

    tox_IP_Port _remote;

    if ( !_mode )
        return print_help ( argv[0] );

    if ( _mode[0] == 'r' ) {
        _send_port = 31000;
        _recv_port = 31001;
    } else if ( _mode[0] == 's' && _ip ) {
        _send_port = 31001;
        _recv_port = 31000;
        t_setipport ( _ip, _send_port, &_remote );
    } else return print_help ( argv[0] );


    /* Bind local receive port to any address */
    IP_Port _local = { { htonl ( INADDR_ANY ) }, _recv_port };
    Networking_Core* _networking = new_networking ( _local.ip, _recv_port );

    if ( !_networking ) {
        fprintf ( stderr, "new_networking() failed!\n" );
        return FAILURE;
    }

    _socket = _networking->sock;

    _m_session = msi_init_session ( _socket );

    if ( !_m_session ) {
        fprintf ( stderr, "msi_init_session() failed\n" );
        return FAILURE;
    }

    /* Initiate callbacks */
    msi_register_callback_send ( sendpacket ); /* Using core's send */
    /*msi_register_callback_recv(receivepacket);*/



    msi_register_callback_call_started ( callback_call_started );
    msi_register_callback_call_canceled ( callback_call_canceled );
    msi_register_callback_call_rejected ( callback_call_rejected );
    msi_register_callback_call_ended ( callback_call_ended );

    msi_register_callback_recv_invite ( callback_recv_invite );
    msi_register_callback_recv_trying ( callback_recv_trying );
    msi_register_callback_recv_ringing ( callback_recv_ringing );
    msi_register_callback_recv_starting ( callback_recv_starting );
    msi_register_callback_recv_ending ( callback_recv_ending );
    /* ------------------ */

    /* Start receive thread */
    pthread_t _recv_thread;
    _status = pthread_create ( &_recv_thread, NULL, phone_receivepacket, _m_session );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        return _status;
    }

    _status = pthread_detach ( _recv_thread );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
    }
    /* -------------------- */

    /* Now start main loop. It's a must! */
    msi_start_main_loop ( _m_session );


    /* This is basically how you handle the protocol */

    if ( _mode[0] == 's' ) { /* Do sender protocol */
        _m_session->_friend_id = _remote;

        msi_invite ( _m_session );
        printf ( "Started call. Press ctrl+c to exit!\n" );

        while ( 1 ) { usleep ( 1000000 ); }

    } else {

        printf ( "Waiting for call. Press ctrl+c to exit!\n" );

        while ( 1 ) { usleep ( 1000000 ); }

    }
    pthread_mutex_destroy ( &_mutex );

    return SUCCESS;
}























