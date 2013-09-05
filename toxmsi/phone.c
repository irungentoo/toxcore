#define _BSD_SOURCE


#include "msi_impl.h"
#include "msi_message.h"
#include "rtp_message.h"
#include "toxrtp/tests/test_helper.h"
#include <assert.h>
#include <unistd.h>
#include "AV_codec.h"


static media_session_t* _m_session = NULL; /* for the sake of test */

pthread_mutex_t _mutex;

static int _socket;
codec_state      *cs;


/* My recv functions */
int rtp_handlepacket ( rtp_session_t* _session, rtp_msg_t* _msg )
{
    if ( !_msg )
        return FAILURE;

    if ( rtp_check_late_message(_session, _msg) < 0 ) {
        rtp_register_msg(_session, _msg);
    }

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
    rtp_msg_t* _msg;

    uint32_t  _bytes;
    tox_IP_Port   _from;
    uint8_t _socket_data[MAX_UDP_PACKET_SIZE];

    int _m_socket = _socket;

    uint16_t _payload_id;

    while ( _session ) {

        int _status = receivepacket ( _m_socket, &_from, _socket_data, &_bytes );
        if ( _status == FAILURE ) { /* nothing recved */
            usleep(2000);
            continue;
        }

        pthread_mutex_lock ( &_mutex );
        switch ( _socket_data[0] ) {
        case MSI_PACKET:
            msi_handlepacket ( _session, _from, _socket_data + 1, _bytes );
            usleep(1000);
            break;
        case RTP_PACKET:
            if ( _session->_call_info == call_active ) {
                /* this will parse a data into rtp_message_t form but
                 * it will not be registered into a session. For that
                 * we need to call a rtp_register_msg ()
                 */
                _msg = rtp_msg_parse ( NULL, _socket_data + 1, _bytes );

                if ( !_msg )
                    break;

                _payload_id = rtp_header_get_setting_payload_type(_msg->_header);

                if ( _payload_id == _PAYLOAD_OPUS && _session->_rtp_audio )
                    rtp_handlepacket ( _session->_rtp_audio, _msg );
                else if ( _payload_id == _PAYLOAD_VP8 && _session->_rtp_video )
                    rtp_handlepacket ( _session->_rtp_video, _msg );
                else rtp_free_msg( NULL, _msg);
            }
            usleep(1000);
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
    rtp_session_t* _rtp_audio;
    rtp_session_t* _rtp_video;
    int* _thread_running;
} hmtc_args_t;

void* handle_media_transport_callback ( void* _hmtc_args_p )
{
    rtp_msg_t* _audio_msg, * _video_msg;

    hmtc_args_t* _hmtc_args = _hmtc_args_p;

    rtp_session_t* _rtp_audio = _hmtc_args->_rtp_audio;
    rtp_session_t* _rtp_video = _hmtc_args->_rtp_video;

    int* _thread_running = _hmtc_args->_thread_running;

    int* _res_position = &_rtp_video->_exthdr_resolution;

    int _m_socket = _socket;

    while ( *_thread_running ) {
        /*
        * This part checks for received messages and if gotten one
        * display 'Received msg!' indicator and free message
        */
        _audio_msg = rtp_recv_msg ( _rtp_audio );
        _video_msg = rtp_recv_msg ( _rtp_video );

        if ( _audio_msg ) {
            /* Do whatever with msg */
            puts("audio");
            rtp_free_msg ( _rtp_audio, _audio_msg );
        }

        if ( _video_msg ) {
            /* Do whatever with msg */
            /* Some example use of marker setters */
            printf("H:%d | W:%d\t",
                   rtp_get_resolution_marking_height(_video_msg->_ext_header, *_res_position),
                   rtp_get_resolution_marking_width(_video_msg->_ext_header, *_res_position));

            if ( rtp_get_resolution_marking_height(_video_msg->_ext_header, *_res_position) < 4000 ){
                //rtp_remove_resolution_marking(_rtp_video);
                rtp_add_resolution_marking(_rtp_video,
                                           rtp_get_resolution_marking_width(_video_msg->_ext_header, *_res_position) + 1,
                                           rtp_get_resolution_marking_width(_video_msg->_ext_header, *_res_position) + 1);
            }

            printf("RM:%d\t", rtp_get_framerate_marking(_video_msg->_ext_header));

            if ( rtp_get_framerate_marking(_video_msg->_ext_header) < 4000 ){
                //rtp_remove_framerate_marking(_rtp_video);
                rtp_add_framerate_marking(_rtp_video, rtp_remove_framerate_marking(_rtp_video));
            }

            rtp_free_msg ( _rtp_video, _video_msg );
        }
        /* -------------------- */

        /*
        * This one makes a test msg and sends that message to the 'remote'
        */
        _audio_msg = rtp_msg_new ( _rtp_audio, (const uint8_t*)"abcd", 4 ) ;
        rtp_send_msg ( _rtp_audio, _audio_msg, _m_socket );

        _video_msg = rtp_msg_new ( _rtp_video, (const uint8_t*)"abcd", 4 ) ;
        rtp_send_msg ( _rtp_video, _video_msg, _m_socket );


        usleep ( 10000 );
        /* -------------------- */
    }

    *_thread_running = -1;

    pthread_exit ( NULL );
}

/* This is call control callback */
void* handle_call_callback ( void* _p )
{
    int _status;

    pthread_t _rtp_tid;
    int _rtp_thread_running = 1;
    cs->_rtp_audio = _m_session->_rtp_audio = rtp_init_session ( -1, 1 );
    cs->_rtp_video = _m_session->_rtp_video = rtp_init_session ( -1, 1 );

    rtp_add_receiver ( cs->_rtp_audio, &_m_session->_friend_id );
    rtp_add_receiver ( cs->_rtp_video, &_m_session->_friend_id );

    rtp_add_resolution_marking(cs->_rtp_video, 1000, 1000);
    rtp_add_framerate_marking( cs->_rtp_video, 100000023);

    uint8_t _prefix = RTP_PACKET;
    rtp_set_prefix ( cs->_rtp_audio, &_prefix, 1 );
    rtp_set_prefix ( cs->_rtp_video, &_prefix, 1 );

    rtp_set_payload_type(cs->_rtp_audio, _PAYLOAD_OPUS);
    rtp_set_payload_type(cs->_rtp_video, _PAYLOAD_VP8);

    hmtc_args_t rtp_targs = { cs->_rtp_audio, cs->_rtp_video, &_rtp_thread_running };

    cs->socket=_socket;
    cs->quit = 0;
    if(cs->support_send_audio&&cs->support_send_video) /* quick fix */
        pthread_create(&cs->encode_audio_thread, NULL, encode_audio_thread, cs);
    if(cs->support_receive_audio)
	pthread_create(&cs->decode_audio_thread, NULL, decode_audio_thread, cs);
    if(cs->support_send_video)
        pthread_create(&cs->encode_video_thread, NULL, encode_video_thread, cs);
    if(cs->support_receive_video)
     	pthread_create(&cs->decode_video_thread, NULL, decode_video_thread, cs); 
    //if(cs->support_receive_video||cs->support_receive_audio)
      //  pthread_create(&cs->decode_thread, NULL, decode_thread, cs);

    _p = NULL;
    char _choice [10];

    do {
        gets ( _choice );
        if ( strcmp ( _choice, "h" ) == 0 ) {
            printf ( "Hanging up...\n" );
            cs->quit=1;
            _status = msi_hangup ( _m_session );
            break;
        }
    } while ( strcmp ( _choice, "c" ) == 0 );

    sleep(100000);
    _handle_call_tid = 0;
    pthread_exit ( &_status );
}


/* Some example callbacks */

MCBTYPE callback_recv_invite ( MCBARGS )
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
MCBTYPE callback_recv_trying ( MCBARGS )
{
    printf ( "Trying...\n" );
    return SUCCESS;
}
MCBTYPE callback_recv_ringing ( MCBARGS )
{
    printf ( "Ringing...\n" );
    return SUCCESS;
}
MCBTYPE callback_recv_starting ( MCBARGS )
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
MCBTYPE callback_recv_ending ( MCBARGS )
{
    printf ( "Call ended! (exiting)\n" );
    pthread_mutex_destroy ( &_mutex );
    exit ( SUCCESS );
    return SUCCESS;
}


MCBTYPE callback_call_started ( MCBARGS )
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
MCBTYPE callback_call_canceled ( MCBARGS )
{
    printf ( "On call canceled!\n" );
    return SUCCESS;
}
MCBTYPE callback_call_rejected ( MCBARGS )
{
    printf ( "Call rejected!\n" );
    return SUCCESS;
}
MCBTYPE callback_call_ended ( MCBARGS )
{
    printf ( "On call ended (exiting)!\n" );

    cs->quit=1;
    pthread_join(cs->encode_video_thread,NULL);
    pthread_join(cs->encode_audio_thread,NULL);
    pthread_join(cs->decode_thread,NULL);

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

    cs = av_mallocz(sizeof(codec_state));

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
    IP_Port _local;
    _local.ip.i = htonl ( INADDR_ANY );
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

    /* Initiate codecs */
    init_encoder(cs);
    init_decoder(cs);

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

        while ( 1 ) {
            usleep ( 1000000 );
        }

    } else {

        printf ( "Waiting for call. Press ctrl+c to exit!\n" );

        while ( 1 ) {
            usleep ( 1000000 );
        }

    }
    pthread_mutex_destroy ( &_mutex );

    return SUCCESS;
}























