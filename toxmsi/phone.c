
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define _BSD_SOURCE
#define _GNU_SOURCE

#define _CT_PHONE

#ifdef _CT_PHONE
#include "phone.h"
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <termios.h>


void INFO (const char* _format, ...)
{
    printf("\r[!] ");
    va_list _arg;
    va_start (_arg, _format);
    vfprintf (stdout, _format, _arg);
    va_end (_arg);
    printf("\n\r >> ");
    fflush(stdout);
}

int rtp_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length )
{
    phone_t* _phone = _object;
    rtp_msg_t* _msg;
    uint8_t _payload_id;

    if ( _phone->_msi->_call && _phone->_msi->_call->_state == call_active ){

        _msg = rtp_msg_parse ( NULL, data + 1, length - 1 ); /* ignore marker byte */

        if ( !_msg )
            return 0;

        _payload_id = rtp_header_get_setting_payload_type(_msg->_header);

        if ( _payload_id == _PAYLOAD_OPUS && _phone->_rtp_audio )
            rtp_store_msg(_phone->_rtp_audio, _msg);
        else if ( _payload_id == _PAYLOAD_VP8 && _phone->_rtp_video )
            rtp_store_msg(_phone->_rtp_video, _msg);
        else rtp_free_msg( NULL, _msg);
    }

    return SUCCESS;
}
int msi_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length )
{
    msi_session_t* _session = _object;
    msi_msg_t* _msg;

    _msg = msi_parse_msg ( data + 1 ); /* ignore marker byte */

    if ( _msg ) {
        /* my current solution for "hole punching" */
        _session->_friend_id = ip_port;
    } else {
        return FAILURE;
    }

    /* place message in a session */
    msi_store_msg(_session, _msg);

    return SUCCESS;
}

void* phone_receivepacket ( void* _phone_p )
{
    phone_t* _phone = _phone_p;


    networking_registerhandler(_phone->_networking, MSI_PACKET, msi_handlepacket, _phone->_msi);
    networking_registerhandler(_phone->_networking, RTP_PACKET, rtp_handlepacket, _phone);

    /* Now start main networking loop */
    while ( _phone->_networking ) { /* so not thread safe */
        networking_poll(_phone->_networking);
        usleep(10000);
    }

    pthread_exit ( NULL );
}

/* Media transport callback */
typedef struct hmtc_args_s {
    rtp_session_t** _rtp_audio;
    rtp_session_t** _rtp_video;
    call_type* _local_type_call;
    call_state* _this_call;
    void *_core_handler;
} hmtc_args_t;

void* phone_handle_media_transport_poll ( void* _hmtc_args_p )
{
    rtp_msg_t* _audio_msg, * _video_msg;

    hmtc_args_t* _hmtc_args = _hmtc_args_p;

    rtp_session_t* _rtp_audio = *_hmtc_args->_rtp_audio;
    rtp_session_t* _rtp_video = *_hmtc_args->_rtp_video;

    call_type* _type = _hmtc_args->_local_type_call;
    void* _core_handler = _hmtc_args->_core_handler;


    call_state* _this_call = _hmtc_args->_this_call;

    while ( *_this_call == call_active ) {

        THREADLOCK()

        _audio_msg = rtp_recv_msg ( _rtp_audio );
        _video_msg = rtp_recv_msg ( _rtp_video );

        if ( _audio_msg ) {
            /* Do whatever with msg
            puts(_audio_msg->_data);*/
            rtp_free_msg ( _rtp_audio, _audio_msg );
        }

        if ( _video_msg ) {
            /* Do whatever with msg
            puts(_video_msg->_data); */
            rtp_free_msg ( _rtp_video, _video_msg );
            _video_msg = NULL;
        }
        /* -------------------- */

        /*
         * Make a test msg and send that message to the 'remote'
         */
        _audio_msg = rtp_msg_new ( _rtp_audio, (const uint8_t*)"audio\0", 6 ) ;
        rtp_send_msg ( _rtp_audio, _audio_msg, _core_handler );
        _audio_msg = NULL;

        if ( *_type == type_video ){ /* if local call send video */
            _video_msg = rtp_msg_new ( _rtp_video, (const uint8_t*)"video\0", 6 ) ;
            rtp_send_msg ( _rtp_video, _video_msg, _core_handler );
            _video_msg = NULL;
        }

        THREADUNLOCK()

        usleep ( 10000 );
        /* -------------------- */
    }

    THREADLOCK()

    if ( _audio_msg ){
        rtp_free_msg(_rtp_audio, _audio_msg);
    }

    if ( _video_msg ) {
        rtp_free_msg(_rtp_video, _video_msg);
    }

    rtp_release_session_recv(_rtp_video);
    rtp_release_session_recv(_rtp_audio);

    rtp_terminate_session(_rtp_audio);
    rtp_terminate_session(_rtp_video);

    *_hmtc_args->_rtp_audio = NULL;
    *_hmtc_args->_rtp_video = NULL;

    free(_hmtc_args_p);

    THREADUNLOCK()

    INFO("Media thread finished!");

    pthread_exit ( NULL );
}

pthread_t phone_startmedia_loop ( phone_t* _phone )
{
    if ( !_phone ){
        return 0;
    }

    int _status;

    uint8_t _prefix = RTP_PACKET;

    pthread_t _rtp_tid;

    _phone->_rtp_audio = rtp_init_session ( -1, 1 );
    rtp_set_prefix ( _phone->_rtp_audio, &_prefix, 1 );
    rtp_add_receiver ( _phone->_rtp_audio, &_phone->_msi->_friend_id );
    rtp_set_payload_type(_phone->_rtp_audio, _PAYLOAD_OPUS);

    _phone->_rtp_video = rtp_init_session ( -1, 1 );
    rtp_set_payload_type(_phone->_rtp_video, _PAYLOAD_VP8);
    rtp_add_receiver ( _phone->_rtp_video, &_phone->_msi->_friend_id );
    rtp_set_prefix ( _phone->_rtp_video, &_prefix, 1 );

    hmtc_args_t* rtp_targs = malloc(sizeof(hmtc_args_t));

    rtp_targs->_rtp_audio = &_phone->_rtp_audio;
    rtp_targs->_rtp_video = &_phone->_rtp_video;
    rtp_targs->_local_type_call = &_phone->_msi->_call->_type_local;
    rtp_targs->_this_call = &_phone->_msi->_call->_state;
    rtp_targs->_core_handler = _phone->_networking;


    _status = pthread_create ( &_rtp_tid, NULL, phone_handle_media_transport_poll, rtp_targs );

    if ( _status < 0 ) {
        printf ( "Error while starting media transport: %d, %s\n", errno, strerror ( errno ) );
        return FAILURE;
    }

    _status = pthread_detach ( _rtp_tid );

    if ( _status < 0 ) {
        printf ( "Error while starting media transport: %d, %s\n", errno, strerror ( errno ) );
        return FAILURE;
    }


    _phone->_medialoop_id = _rtp_tid;

    return _rtp_tid;
}


/* Some example callbacks */

MCBTYPE callback_recv_invite ( MCBARGS )
{
    const char* _call_type;

    msi_session_t* _msi = _arg;

    /* Get the last one */
    call_type _type = _msi->_call->_type_peer[_msi->_call->_participants - 1];

    switch ( _type ){
    case type_audio:
        _call_type = "audio";
        break;
    case type_video:
        _call_type = "video";
        break;
    }

    INFO( "Incoming %s call!", _call_type );

}
MCBTYPE callback_recv_trying ( MCBARGS )
{
    INFO ( "Trying...");
}
MCBTYPE callback_recv_ringing ( MCBARGS )
{
    INFO ( "Ringing!" );
}
MCBTYPE callback_recv_starting ( MCBARGS )
{
    msi_session_t* _session = _arg;
    if ( !phone_startmedia_loop(_session->_agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }
}
MCBTYPE callback_recv_ending ( MCBARGS )
{
    INFO ( "Call ended!" );
}


MCBTYPE callback_call_started ( MCBARGS )
{
    msi_session_t* _session = _arg;
    if ( !phone_startmedia_loop(_session->_agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }

}
MCBTYPE callback_call_canceled ( MCBARGS )
{
    INFO ( "Call canceled!" );
}
MCBTYPE callback_call_rejected ( MCBARGS )
{
    INFO ( "Call rejected!\n" );
}
MCBTYPE callback_call_ended ( MCBARGS )
{
    INFO ( "Call ended!" );
}

phone_t* initPhone(uint16_t _listen_port, uint16_t _send_port)
{
    phone_t* _retu = malloc(sizeof(phone_t));

    /* Initialize our mutex */
    pthread_mutex_init ( &_mutex, NULL );

    IP_Port _local;
    ip_init(&_local.ip, 0);
    _local.ip.ip4.uint32 = htonl ( INADDR_ANY );

    /* Bind local receive port to any address */
    _retu->_networking = new_networking ( _local.ip, _listen_port );

    if ( !_retu->_networking ) {
        fprintf ( stderr, "new_networking() failed!\n" );
        return NULL;
    }

    _retu->_send_port = _send_port;
    _retu->_recv_port = _listen_port;

    _retu->_tox_sock = _retu->_networking->sock;

    _retu->_rtp_audio = NULL;
    _retu->_rtp_video = NULL;


    /* Initialize msi */
    _retu->_msi = msi_init_session ( _retu->_networking, (const uint8_t*)_USERAGENT );

    if ( !_retu->_msi ) {
        fprintf ( stderr, "msi_init_session() failed\n" );
        return NULL;
    }


    _retu->_msi->_agent_handler = _retu;
    /* Initiate callbacks */
    msi_register_callback_send ( sendpacket ); /* Using core's send */

    msi_register_callback_call_started ( callback_call_started );
    msi_register_callback_call_canceled ( callback_call_canceled );
    msi_register_callback_call_rejected ( callback_call_rejected );
    msi_register_callback_call_ended ( callback_call_ended );

    msi_register_callback_recv_invite ( callback_recv_invite );
    msi_register_callback_recv_ringing ( callback_recv_ringing );
    msi_register_callback_recv_starting ( callback_recv_starting );
    msi_register_callback_recv_ending ( callback_recv_ending );
    /* ------------------ */

    /* Now start msi main loop. It's a must!
     * Define a frequency in ms; 10 ms is just fine
     */
    msi_start_main_loop ( _retu->_msi, 10 );

    return _retu;
}

pthread_t phone_startmain_loop(phone_t* _phone)
{
    int _status;
    /* Start receive thread */
    pthread_t _recv_thread, _phone_loop_thread;
    _status = pthread_create ( &_recv_thread, NULL, phone_receivepacket, _phone );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_detach ( _recv_thread );

    if ( _status < 0 ) {
        printf ( "Error while starting handle call: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_create ( &_phone_loop_thread, NULL, phone_poll, _phone );

    if ( _status < 0 ) {
        printf ( "Error while starting main phone loop: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    _status = pthread_join ( _phone_loop_thread, NULL );

    if ( _status < 0 ) {
        printf ( "Error while starting main phone loop: %d, %s\n", errno, strerror ( errno ) );
        return 0;
    }

    return _phone_loop_thread;
}

void* phone_poll ( void* _p_phone )
{
    phone_t* _phone = _p_phone;

    int _status = SUCCESS;

    char* _line;
    size_t _len;


    char _dest[17]; /* For parsing destination ip */
    memset(_dest, '\0', 17);

    INFO("Welcome to tox_phone version: " _USERAGENT "\n"
         "Usage: \n"
         "c [a/v] (type) [0.0.0.0] (dest ip) (calls dest ip)\n"
         "h (if call is active hang up)\n"
         "a [a/v] (answer incoming call: a - audio / v - audio + video (audio is default))\n"
         "r (reject incoming call)\n"
         "q (quit)\n"
         "================================================================================"
         );

    while ( 1 )
    {
        getline(&_line, &_len, stdin);

        if ( !_len ){
            printf(" >> "); fflush(stdout);
            continue;
        }

        if ( _len > 1 && _line[1] != ' ' && _line[1] != '\n' ){
            INFO("Invalid input!");
            continue;
        }

        switch (_line[0]){

        case 'c':
        {
            if ( _phone->_msi->_call ){
                INFO("Already in a call");
                break;
            }

            call_type _ctype;
            if ( _len < 11 ){
                INFO("Invalid input; usage: c a/v 0.0.0.0");
                break;
            }
            else if ( _line[2] == 'a' || _line[2] != 'v' ){ /* default and audio */
                _ctype = type_audio;
            }
            else { /* video */
                _ctype = type_video;
            }

            strcpy(_dest, _line + 4 );
            _status = t_setipport(_dest, _phone->_send_port, &(_phone->_msi->_friend_id));

            if ( _status < 0 ){
                INFO("Could not resolve address!");
            } else {
                /* Set timeout */
                msi_invite ( _phone->_msi, _ctype, 30 * 1000 );
                INFO("Calling!");
            }

            t_memset((uint8_t*)_dest, '\0', 17);

        } break;
        case 'h':
        {
            if ( !_phone->_msi->_call ){
                break;
            }

            msi_hangup(_phone->_msi);

            INFO("Hung up...");

        } break;
        case 'a':
        {
            if ( _phone->_msi->_call && _phone->_msi->_call->_state != call_starting ) {
                break;
            }

            if ( _len > 1 && _line[2] == 'v' )
                msi_answer(_phone->_msi, type_video);
            else
                msi_answer(_phone->_msi, type_audio);

        } break;
        case 'r':
        {
            if ( _phone->_msi->_call && _phone->_msi->_call->_state != call_starting ){
                break;
            }

            msi_reject(_phone->_msi);

            INFO("Call Rejected...");

        } break;
        case 'q':
        {
            INFO("Quitting!");
            pthread_exit(NULL);
        }
        default:
        {
            INFO("Invalid command!");
        } break;

        }

    }

    pthread_exit(NULL);
}

int quitPhone(phone_t* _phone)
{
    if ( _phone->_msi->_call ){
        msi_hangup(_phone->_msi); /* Hangup the phone first */
    }

    msi_terminate_session(_phone->_msi);
    pthread_mutex_destroy ( &_mutex );

    printf("\rQuit!\n");
    return SUCCESS;
}

/* ---------------------- */

int print_help ( const char* _name )
{
    printf ( "Usage: %s -m (mode) -r/s ( for setting the ports on test version )\n", _name );
    return FAILURE;
}

int main ( int argc, char* argv [] )
{
    arg_t* _args = parse_args ( argc, argv );

    const char* _mode = find_arg_duble ( _args, "-m" );
    uint16_t _listen_port;
    uint16_t _send_port;

    if ( !_mode )
        return print_help ( argv[0] );

    if ( _mode[0] == 'r' ) {
        _send_port = 31000;
        _listen_port = 31001;
    } else if ( _mode[0] == 's' ) {
        _send_port = 31001;
        _listen_port = 31000;
    } else return print_help ( argv[0] );

    phone_t* _phone = initPhone(_listen_port, _send_port);

    if ( _phone ){
        phone_startmain_loop(_phone);

        quitPhone(_phone);
    }

    return SUCCESS;
}

#endif /* _CT_PHONE */
