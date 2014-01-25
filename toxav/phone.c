/**  phone.c
 *
 *   NOTE NOTE NOTE NOTE NOTE NOTE 
 * 
 *   This file is for testing/reference purposes only, hence
 *   it is _poorly_ designed and it does not fully reflect the 
 *   quaility of msi nor rtp. Although toxmsi* and toxrtp* are tested 
 *   there is always possiblity of crashes. If crash occures, 
 *   contact me ( mannol ) on either irc channel #tox-dev @ freenode.net:6667 
 *   or eniz_vukovic@hotmail.com
 * 
 *   NOTE NOTE NOTE NOTE NOTE NOTE 
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

#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "toxmsi.h"
#include "toxrtp.h"
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>

#include "../toxcore/network.h"
#include "../toxcore/event.h"
#include "../toxcore/tox.h"

/* Define client version */
#define _USERAGENT "v.0.3.0"


typedef struct av_friend_s {
    int _id;
    int _active; /* 0=false; 1=true; */
} av_friend_t;

typedef struct av_session_s {
    MSISession* _msi;

    RTPSession* _rtp_audio;
    RTPSession* _rtp_video;

    pthread_mutex_t _mutex;
    
    Tox* _messenger;
    av_friend_t*  _friends;
    int _friend_cout;
    uint8_t _my_public_id[200];
} av_session_t;


void av_allocate_friend(av_session_t* _phone, int _id, int _active)
{
    static int _new_id = 0;
    
    if ( !_phone->_friends ) {
        _phone->_friends = calloc(sizeof(av_friend_t), 1);
        _phone->_friend_cout = 1;
    } else{
        _phone->_friend_cout ++;
        _phone->_friends = realloc(_phone->_friends, sizeof(av_friend_t) * _phone->_friend_cout);
    }
    
    if ( _id = -1 ) {
        _phone->_friends->_id = _new_id;
        _new_id ++;
    } else _phone->_friends->_id = _id;
    
    _phone->_friends->_active = _active;
}
av_friend_t* av_get_friend(av_session_t* _phone, int _id)
{
    av_friend_t* _friends = _phone->_friends;
    
    if ( !_friends ) return NULL;
    
    int _it = 0;
    for (; _it < _phone->_friend_cout; _it ++)
        if ( _friends[_it]._id == _id ) 
            return _friends + _it;
    
    return NULL;
}


/***************** MISC *****************/

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

unsigned char *hex_string_to_bin(char hex_string[])
{
    size_t i, len = strlen(hex_string);
    unsigned char *val = calloc(sizeof(char), len);
    char *pos = hex_string;
    
    for (i = 0; i < len; ++i, pos += 2)
        sscanf(pos, "%2hhx", &val[i]);
    
    return val;
}

int getinput( char* _buff, size_t _limit, int* _len )
{
    if ( fgets(_buff, _limit, stdin) == NULL )
        return -1;
    
    *_len = strlen(_buff) - 1;
    
    /* Get rid of newline */
    _buff[*_len] = '\0';
    
    return 0;
}

char* trim_spaces ( char* buff )
{
    
    int _i = 0, _len = strlen(buff);
    
    char* container = calloc(sizeof(char), _len);
    int _ci = 0;
    
    for ( ; _i < _len; _i++ ) {
        while ( _i < _len && buff[_i] == ' ' )
            _i++;
        
        if ( _i < _len ){
            container[_ci] = buff[_i];
            _ci ++;
        }
    }
    
    memcpy( buff, container, _ci );
    buff[_ci] = '\0';
    free(container);
    return buff;
}

#define FRADDR_TOSTR_CHUNK_LEN 8

static void fraddr_to_str(uint8_t *id_bin, char *id_str)
{    
    uint i, delta = 0, pos_extra, sum_extra = 0;
    
    for (i = 0; i < TOX_FRIEND_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);
        
        if ((i + 1) == TOX_CLIENT_ID_SIZE)
            pos_extra = 2 * (i + 1) + delta;
        
        if (i >= TOX_CLIENT_ID_SIZE)
            sum_extra |= id_bin[i];
        
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
    }
    
    id_str[2 * i + delta] = 0;
    
    if (!sum_extra)
        id_str[pos_extra] = 0;
}

void* phone_handle_media_transport_poll ( void* _hmtc_args_p )
{
    RTPMessage* _audio_msg, * _video_msg;
    av_session_t* _phone = _hmtc_args_p;
    MSISession* _session = _phone->_msi;

    RTPSession* _rtp_audio = _phone->_rtp_audio;
    RTPSession* _rtp_video = _phone->_rtp_video;

        
    Tox* _messenger = _phone->_messenger;
    
    
    while ( _session->call ) {

        _audio_msg = rtp_recv_msg ( _rtp_audio );
        _video_msg = rtp_recv_msg ( _rtp_video );

        if ( _audio_msg ) {
            /* Do whatever with msg
            printf("%d - %s\n", _audio_msg->header->sequnum, _audio_msg->data);*/
            rtp_free_msg ( _rtp_audio, _audio_msg );
        }

        if ( _video_msg ) {
            /* Do whatever with msg
             p rintf("%d - %s\n", _video_msg->header->sequnum, _video_msg->data);*/
            rtp_free_msg ( _rtp_video, _video_msg );
        }

        /*
         * Send test message to the 'remote'
         */
        rtp_send_msg ( _rtp_audio, _messenger, (const uint8_t*)"audio\0", 6 );

        if ( _session->call->type_local == type_video ){ /* if local call send video */
            rtp_send_msg ( _rtp_video, _messenger, (const uint8_t*)"video\0", 6 );
        }

        _audio_msg = _video_msg = NULL;
        
        
        /* Send ~1k messages per second 
         * That _should_ be enough for both Audio and Video
         */
        usleep ( 1000 );
        /* -------------------- */
    }
    
    if ( _audio_msg ) rtp_free_msg(_rtp_audio, _audio_msg);
    rtp_release_session_recv(_rtp_audio);
    rtp_terminate_session(_rtp_audio, _messenger);
    
    if ( _video_msg ) rtp_free_msg(_rtp_video, _video_msg);
    rtp_release_session_recv(_rtp_video);
    rtp_terminate_session(_rtp_video, _messenger);
    
    INFO("Media thread finished!");

    pthread_exit ( NULL );
}

int phone_startmedia_loop ( av_session_t* _phone )
{
    if ( !_phone ){
        return -1;
    }

    _phone->_rtp_audio = rtp_init_session ( 
        type_audio,
        _phone->_messenger, 
        _phone->_msi->call->peers[0],
        _phone->_msi->call->key_peer,
        _phone->_msi->call->key_local,
        _phone->_msi->call->nonce_peer,
        _phone->_msi->call->nonce_local
        );
    
    _phone->_rtp_audio = rtp_init_session ( 
        type_video,
        _phone->_messenger, 
        _phone->_msi->call->peers[0],
        _phone->_msi->call->key_peer,
        _phone->_msi->call->key_local,
        _phone->_msi->call->nonce_peer,
        _phone->_msi->call->nonce_local
        );


    if ( 0 > event.rise(phone_handle_media_transport_poll, _phone) )
    {
        printf("Error while starting phone_handle_media_transport_poll()\n");
        return -1;
    }
    else return 0;
}


/* Some example callbacks */

void* callback_recv_invite ( void* _arg )
{
    const char* _call_type;

    MSISession* _msi = _arg;

    switch ( _msi->call->type_peer[_msi->call->peer_count - 1] ){
    case type_audio:
        _call_type = "audio";
        break;
    case type_video:
        _call_type = "video";
        break;
    }

    INFO( "Incoming %s call!", _call_type );

}
void* callback_recv_ringing ( void* _arg )
{
    INFO ( "Ringing!" );
}
void* callback_recv_starting ( void* _arg )
{
    MSISession* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }
}
void* callback_recv_ending ( void* _arg )
{
    INFO ( "Call ended!" );
}

void* callback_recv_error ( void* _arg )
{
    MSISession* _session = _arg;

    INFO( "Error: %s", _session->last_error_str );
}

void* callback_call_started ( void* _arg )
{
    MSISession* _session = _arg;
    if ( 0 != phone_startmedia_loop(_session->agent_handler) ){
        INFO("Starting call failed!");
    } else {
        INFO ("Call started! ( press h to hangup )");
    }

}
void* callback_call_canceled ( void* _arg )
{
    INFO ( "Call canceled!" );
}
void* callback_call_rejected ( void* _arg )
{
    INFO ( "Call rejected!" );
}
void* callback_call_ended ( void* _arg )
{
    INFO ( "Call ended!" );
}

void* callback_requ_timeout ( void* _arg )
{
    INFO( "No answer! " );
}

int av_connect_to_dht(av_session_t* _phone, char* _dht_key, const char* _dht_addr, unsigned short _dht_port)
{
    unsigned char *_binary_string = hex_string_to_bin(_dht_key);
       
    uint16_t _port = htons(_dht_port);
    
    int _if = tox_bootstrap_from_address(_phone->_messenger, _dht_addr, 1, _port, _binary_string );
    
    free(_binary_string);
    
    return _if ? 0 : -1;
}

av_session_t* av_init_session()
{
    av_session_t* _retu = malloc(sizeof(av_session_t));

    /* Initialize our mutex */
    pthread_mutex_init ( &_retu->_mutex, NULL );

    _retu->_messenger = tox_new(1);
    
    if ( !_retu->_messenger ) {
        fprintf ( stderr, "tox_new() failed!\n" );
        return NULL;
    }

    _retu->_friends = NULL;
    
    _retu->_rtp_audio = NULL;
    _retu->_rtp_video = NULL;
    
    uint8_t _byte_address[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(_retu->_messenger, _byte_address );
    fraddr_to_str( _byte_address, _retu->_my_public_id );
    
    
    /* Initialize msi */
    _retu->_msi = msi_init_session ( _retu->_messenger, _USERAGENT );

    if ( !_retu->_msi ) {
        fprintf ( stderr, "msi_init_session() failed\n" );
        return NULL;
    }

    _retu->_msi->agent_handler = _retu;

    /* ------------------ */
    msi_register_callback(callback_call_started, cb_onstart);
    msi_register_callback(callback_call_canceled, cb_oncancel);
    msi_register_callback(callback_call_rejected, cb_onreject);
    msi_register_callback(callback_call_ended, cb_onend);
    msi_register_callback(callback_recv_invite, cb_oninvite);

    msi_register_callback(callback_recv_ringing, cb_ringing);
    msi_register_callback(callback_recv_starting, cb_starting);
    msi_register_callback(callback_recv_ending, cb_ending);

    msi_register_callback(callback_recv_error, cb_error);
    msi_register_callback(callback_requ_timeout, cb_timeout);
    /* ------------------ */

    return _retu;
}

int av_terminate_session(av_session_t* _phone)
{
    if ( _phone->_msi->call ){
        msi_hangup(_phone->_msi); /* Hangup the phone first */
    }
    
    free(_phone->_friends);
    msi_terminate_session(_phone->_msi);
    pthread_mutex_destroy ( &_phone->_mutex );
    
    Tox* _p = _phone->_messenger;
    _phone->_messenger = NULL; usleep(100000); /* Wait for tox_pool to end */
    tox_kill(_p);
    
    printf("\r[i] Quit!\n");
    return 0;
}

/****** AV HELPER FUNCTIONS ******/

/* Auto accept friend request */
void av_friend_requ(uint8_t *_public_key, uint8_t *_data, uint16_t _length, void *_userdata)
{
    av_session_t* _phone = _userdata;
    av_allocate_friend (_phone, -1, 0);
    
    INFO("Got friend request with message: %s", _data);
    
    tox_add_friend_norequest(_phone->_messenger, _public_key);
    
    INFO("Auto-accepted! Friend id: %d",  _phone->_friends->_id );
}

void av_friend_active(Tox *_messenger, int _friendnumber, uint8_t *_string, uint16_t _length, void *_userdata)
{
    av_session_t* _phone = _userdata;
    INFO("Friend no. %d is online", _friendnumber);
    
    av_friend_t* _this_friend = av_get_friend(_phone, _friendnumber);
    
    if ( !_this_friend ) {
        INFO("But it's not registered!");
        return;
    }
    
    (*_this_friend)._active = 1;
}

int av_add_friend(av_session_t* _phone, char* _friend_hash)
{    
    trim_spaces(_friend_hash);
    
    unsigned char *_bin_string = hex_string_to_bin(_friend_hash);
    int _number = tox_add_friend(_phone->_messenger, _bin_string, (uint8_t *)"Tox phone "_USERAGENT, sizeof("Tox phone "_USERAGENT));
    free(_bin_string);
    
    if ( _number >= 0) {
        INFO("Added friend as %d", _number );
        av_allocate_friend(_phone, _number, 0);
    }
    else
        INFO("Unknown error %i", _number );
    
    return _number;
}
/*********************************/

void do_phone ( av_session_t* _phone )
{
    INFO("Welcome to tox_phone version: " _USERAGENT "\n"
         "Usage: \n"
         "f [pubkey] (add friend)\n"
         "c [a/v] (type) [friend] (friend id) (calls friend if online)\n"
         "h (if call is active hang up)\n"
         "a [a/v] (answer incoming call: a - audio / v - audio + video (audio is default))\n"
         "r (reject incoming call)\n"
         "q (quit)\n"
         "================================================================================"
         );

    while ( 1 )
    {        
        char _line [ 1500 ];
        int _len;
        
        if ( -1 == getinput(_line, 1500, &_len) ){
            printf(" >> "); 
            fflush(stdout);
            continue;
        }
        
        if ( _len > 1 && _line[1] != ' ' && _line[1] != '\n' ){
            INFO("Invalid input!");
            continue;
        }

        switch (_line[0]){

        case 'f':
        {
            char _id [128];
            strncpy(_id, _line + 2, 128);            
            
            av_add_friend(_phone, _id);
                    
        } break;
        case 'c':
        {
            if ( _phone->_msi->call ){
                INFO("Already in a call");
                break;
            }
            
            MSICallType _ctype;
            
            if ( _len < 5 ){
                INFO("Invalid input; usage: c a/v [friend]");
                break;
            }
            else if ( _line[2] == 'a' || _line[2] != 'v' ){ /* default and audio */
                _ctype = type_audio;
            }
            else { /* video */
                _ctype = type_video;
            }
            
            char* _end;
            int _friend = strtol(_line + 4, &_end, 10);
            
            if ( *_end ){
                INFO("Friend num has to be numerical value");
                break;
            }
            
            /* Set timeout */
            msi_invite ( _phone->_msi, _ctype, 10 * 1000, _friend );
            INFO("Calling friend: %d!", _friend);

        } break;
        case 'h':
        {
            if ( !_phone->_msi->call ){
                INFO("No call!");
                break;
            }

            msi_hangup(_phone->_msi);

            INFO("Hung up...");

        } break;
        case 'a':
        {

            if ( _phone->_msi->call && _phone->_msi->call->state != call_starting ) {
                break;
            }

            if ( _len > 1 && _line[2] == 'v' )
                msi_answer(_phone->_msi, type_video);
            else
                msi_answer(_phone->_msi, type_audio);

        } break;
        case 'r':
        {
            if ( _phone->_msi->call && _phone->_msi->call->state != call_starting ){
                break;
            }

            msi_reject(_phone->_msi);

            INFO("Call Rejected...");

        } break;
        case 'q':
        {
            INFO("Quitting!");
            return;
        }
        default:
        {
            INFO("Invalid command!");
        } break;

        }

    }
}

void* tox_poll (void* _messenger_p)
{
    Tox** _messenger = _messenger_p;
    while( *_messenger ) { 
        tox_do(*_messenger); 
        usleep(10000);
    }
        
    pthread_exit(NULL);
}

int av_wait_dht(av_session_t* _phone, int _wait_seconds, const char* _ip, char* _key, unsigned short _port)
{
    if ( !_wait_seconds )
        return -1;
    
    int _waited = 0;
    
    while( !tox_isconnected(_phone->_messenger) ) {
        
        if ( -1 == av_connect_to_dht(_phone, _key, _ip, _port) )
        {
            INFO("Could not connect to: %s", _ip);
            av_terminate_session(_phone);
            return -1;
        }
        
        if ( _waited >= _wait_seconds ) return 0;
        
        printf(".");
        fflush(stdout);
        
        _waited ++;
        usleep(1000000);
    }
    
    int _r = _wait_seconds - _waited;
    return _r ? _r : 1;
}
/* ---------------------- */

int print_help ( const char* _name )
{
    printf ( "Usage: %s [IP] [PORT] [KEY]\n" 
	     "\t[IP] (DHT ip)\n"
	     "\t[PORT] (DHT port)\n"
	     "\t[KEY] (DHT public key)\n"
	     ,_name );
    return 1;
}

int main ( int argc, char* argv [] )
{
    if ( argc < 1 || argc < 4 )
	return print_help(argv[0]);
    
    char* _convertable;
    
    int _wait_seconds = 5;
    
    const char* _ip = argv[1];
    char* _key = argv[3];
    unsigned short _port = strtol(argv[2], &_convertable, 10);
    
    if ( *_convertable ){
	printf("Invalid port: cannot convert string to long: %s", _convertable);
	return 1;
    }
    
    av_session_t* _phone = av_init_session();
    
    tox_callback_friend_request(_phone->_messenger, av_friend_requ, _phone);
    tox_callback_status_message(_phone->_messenger, av_friend_active, _phone);

    system("clear");
    
    INFO("\r================================================================================\n"
         "[!] Trying dht@%s:%d"
         , _ip, _port);
    
    /* Start tox protocol */
    event.rise( tox_poll, &_phone->_messenger );
    
    /* Just clean one line */
    printf("\r       \r");
    fflush(stdout);
    
    int _r;
    for ( _r = 0; _r == 0; _r = av_wait_dht(_phone, _wait_seconds, _ip, _key, _port) ) _wait_seconds --;
    
        
    if ( -1 == _r ) {
        INFO("Error while connecting to dht: %s:%d", _ip, _port);
        av_terminate_session(_phone);
        return 1;
    }
    
    INFO("CONNECTED!\n"
         "================================================================================\n"
         "%s\n"
         "================================================================================"
         , _phone->_my_public_id );

    
    do_phone (_phone);
    
    av_terminate_session(_phone);
    
    return 0;
}
