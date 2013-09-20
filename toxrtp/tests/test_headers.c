/*   test_headers.c
 *
 *   Tests header parsing. You probably won't need this. !Red!
 *
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
 *   along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "test_helper.h"
#include "toxrtp/rtp_impl.h"
#include "../rtp_message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>
#include "toxrtp/rtp_error_id.h"

#define _CT_HEADERS_

#ifdef _CT_HEADERS

int _socket;
pthread_mutex_t _mutex;

int print_help()
{
    puts (
        " Usage: Tuxrtp [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
        "               [-r ( recv mode ) ]"
    );
    return FAILURE;
}

void print_session_stats ( rtp_session_t* _m_session )
{
    printf
    (
        "Session test:\n"
        "\tPackets sent:%d\n"
        "\tPackets recv:%d\n\n"
        "\tBytes   sent:%d\n"
        "\tBytes   recv:%d\n\n"
        "\tHeader CCSRs:%d\n"
        ,
        _m_session->_packets_sent,
        _m_session->_packets_recv,
        _m_session->_bytes_sent,
        _m_session->_bytes_recv,
        _m_session->_cc
    );

    uint8_t i;
    for ( i = 0; i < _m_session->_cc; i++ ) {
        printf (
            "\t%d > :%d\n", i, _m_session->_csrc[i]
        );
    }
}

void print_header_info ( rtp_header_t* _header )
{
    printf
    (
        "Header info:\n"
        "\tVersion              :%d\n"
        "\tPadding              :%d\n"
        "\tExtension            :%d\n"
        "\tCSRC count           :%d\n"
        "\tPayload type         :%d\n"
        "\tMarker               :%d\n\n"

        "\tSSrc                 :%d\n"
        "\tSequence num         :%d\n"
        "\tLenght:              :%d\n"
        "\tCSRC's:\n"
        ,
        rtp_header_get_flag_version ( _header ),
        rtp_header_get_flag_padding ( _header ),
        rtp_header_get_flag_extension ( _header ),
        rtp_header_get_flag_CSRC_count ( _header ),
        rtp_header_get_setting_payload_type ( _header ),
        rtp_header_get_setting_marker ( _header ),

        _header->_ssrc,
        _header->_sequence_number,
        _header->_length
    );


    uint8_t i;
    for ( i = 0; i < rtp_header_get_flag_CSRC_count ( _header ); i++ ) {
        printf (
            "\t%d >                  :%d\n", i, _header->_csrc[i]
        );
    }

    puts ( "\n" );
}

void print_ext_header_info(rtp_ext_header_t* _ext_header)
{
    printf
    (
    "External Header info: \n"
    "\tLenght              :%d\n"
    "\tID                  :%d\n"
    "\tValue H             :%d\n"
    "\tValue W             :%d\n\n",
    _ext_header->_ext_len,
    _ext_header->_ext_type,
    rtp_get_resolution_marking_height(_ext_header, 0),
    rtp_get_resolution_marking_width(_ext_header, 0)
    );
}

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

void* receivepacket_callback(void* _p_session)
{
    rtp_msg_t* _msg;
    rtp_session_t* _session = _p_session;

    uint32_t  _bytes;
    tox_IP_Port   _from;
    uint8_t _socket_data[MAX_UDP_PACKET_SIZE];

    int _m_socket = _socket;

    while ( 1 )
    {
        int _status = receivepacket ( _m_socket, &_from, _socket_data, &_bytes );

        if ( _status == FAILURE ) { /* nothing recved */
            usleep(1000);
            continue;
        }

        pthread_mutex_lock ( &_mutex );

        _msg = rtp_msg_parse ( NULL, _socket_data, _bytes );
        rtp_handlepacket(_session, _msg);

        pthread_mutex_unlock ( &_mutex );
    }

    pthread_exit(NULL);
}

int main ( int argc, char* argv[] )
{
    arg_t* _list = parse_args ( argc, argv );

    if ( _list == NULL ) { /* failed */
        return print_help();
    }

    pthread_mutex_init ( &_mutex, NULL );

    int status;
    IP_Port     Ip_port;
    const char* ip;
    uint16_t    port;


    const uint8_t* test_bytes [300];
    memset(test_bytes, 'a', 300);

    rtp_session_t* _m_session;
    rtp_msg_t*     _m_msg;

    if ( find_arg_simple ( _list, "-r" ) != FAILURE ) { /* Server mode */

        IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
        LOCAL_IP.ip.i = htonl(INADDR_ANY);
        LOCAL_IP.port = RTP_PORT;
        LOCAL_IP.padding = -1;

        _m_session = rtp_init_session ( -1, -1 );
        Networking_Core* _networking = new_networking(LOCAL_IP.ip, RTP_PORT_LISTEN);
        _socket = _networking->sock;


        if ( !_networking ){
            pthread_mutex_destroy ( &_mutex );
            return FAILURE;
        }

        int _socket = _networking->sock;

        if ( status < 0 ) {
            pthread_mutex_destroy ( &_mutex );
            return FAILURE;
        }
        /* -- start in recv mode, get 1 message and then analyze it -- */
        pthread_t _tid;
        RUN_IN_THREAD(receivepacket_callback, _tid, _m_session)

        for ( ; ; ) { /* Recv for x seconds */
            _m_msg = rtp_recv_msg ( _m_session );

            /* _m_msg = rtp_session_get_message_queded ( _m_session ); DEPRECATED */
            if ( _m_msg ) {
                /*rtp_free_msg(_m_session, _m_msg);
                _m_msg = NULL;*/
                printf("Timestamp: %d\n", _m_msg->_header->_timestamp);
            }

            usleep ( 10000 );
        }

        if ( _m_msg->_header ) {
            rtp_header_print ( _m_msg->_header );
        }
        if ( _m_msg->_ext_header ){
            print_ext_header_info(_m_msg->_ext_header);
        }

        //print_session_stats ( _m_session );


        //printf ( "Payload: ( %d ) \n%s\n", _m_msg->_length, _m_msg->_data );


    } else if ( find_arg_simple ( _list, "-s" ) != FAILURE ) {
        ip = find_arg_duble ( _list, "-d" );

        if ( ip == NULL ) {
            pthread_mutex_destroy ( &_mutex );
            return FAILURE;
        }

        const char* _port = find_arg_duble ( _list, "-p" );

        if ( _port != NULL ) {
            port = atoi ( _port );
        }

        t_setipport ( ip, port, &Ip_port );
        printf ( "Remote: %s:%d\n", ip, port );

        Networking_Core* _networking = new_networking(Ip_port.ip, RTP_PORT);

        if ( !_networking ){
            pthread_mutex_destroy ( &_mutex );
            return FAILURE;
        }

        int _socket = _networking->sock;

        _m_session = rtp_init_session ( -1, -1 );
        rtp_add_receiver( _m_session, &Ip_port );
        //rtp_add_resolution_marking(_m_session, 1920, 1080);
        //rtp_add_framerate_marking(_m_session, 1000);

        puts ( "Now sending payload!\n" );
        uint16_t _first_sequ = _m_session->_sequence_number;

        /* use already defined buffer lenght */
        while ( 1 ){
            _m_msg = rtp_msg_new ( _m_session, test_bytes, 300 );
            rtp_send_msg ( _m_session, _m_msg, _socket );
            usleep(10000);
        }

        if ( _m_session->_last_error ) {
            puts ( _m_session->_last_error );
        }

        return rtp_terminate_session(_m_session);

    } else {
        pthread_mutex_destroy ( &_mutex );
        return FAILURE;
    }
    pthread_mutex_destroy ( &_mutex );

    return SUCCESS;
}

#endif /* _CT_HEADERS */
