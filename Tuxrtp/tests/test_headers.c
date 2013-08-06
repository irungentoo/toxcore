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
#include "../rtp_helper.h"
#include "../rtp_handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>


int _print_help()
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

    for ( uint8_t i = 0; i < _m_session->_cc; i++ ) {
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

    for ( uint8_t i = 0; i < rtp_header_get_flag_CSRC_count ( _header ); i++ ) {
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
    rtp_get_resolution_marking_height(_ext_header),
    rtp_get_resolution_marking_width(_ext_header)
    );
}

int _main ( int argc, char* argv[] )
{
    arg_t* _list = parse_args ( argc, argv );

    if ( _list == NULL ) { /* failed */
        return print_help();
    }

    int status;
    IP_Port     Ip_port[1];
    const char* ip;
    uint16_t    port;


    const uint8_t* test_bytes = "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf"
                                "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf"
                                "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf"
                                "asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf\0";

    rtp_session_t* _m_session;
    rtp_msg_t*     _m_msg;

    if ( find_arg_simple ( _list, "-r" ) != FAILURE ) { /* Server mode */

        IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
        LOCAL_IP.ip.i = htonl(INADDR_ANY);
        LOCAL_IP.port = RTP_PORT;
        LOCAL_IP.padding = -1;

        _m_session = rtp_init_session ( LOCAL_IP, -1 );
        status = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );

        if ( status < 0 ) {
            _m_session->_last_error = strerror ( errno );
            puts ( _m_session->_last_error );
            return FAILURE;
        }
        /* -- start in recv mode, get 1 message and then analyze it -- */

        for ( ; ; ) { /* Recv for x seconds */
            _m_msg = rtp_recv_msg ( _m_session );

            /* _m_msg = rtp_session_get_message_queded ( _m_session ); DEPRECATED */
            if ( _m_msg ) {
                DEALLOCATOR_MSG(_m_msg)
                _m_msg = NULL;
                /*break;*/
            }

            usleep ( 100000 );
        }

        if ( _m_msg->_header ) {
            print_header_info ( _m_msg->_header );
        }
        if ( _m_msg->_ext_header ){
            print_ext_header_info(_m_msg->_ext_header);
        }

        print_session_stats ( _m_session );


        printf ( "Payload: ( %d ) \n%s\n", _m_msg->_length, _m_msg->_data );


    } else if ( find_arg_simple ( _list, "-s" ) != FAILURE ) {
        ip = find_arg_duble ( _list, "-d" );

        if ( ip == NULL ) {
            return FAILURE;
        }

        const char* _port = find_arg_duble ( _list, "-p" );

        if ( _port != NULL ) {
            port = atoi ( _port );
        }

        set_ip_port ( ip, port, Ip_port );
        printf ( "Remote: %s:%d\n", ip, port );
        status = init_networking ( Ip_port[0].ip, RTP_PORT );

        _m_session = rtp_init_session ( Ip_port[0], -1 );
        rtp_add_resolution_marking(_m_session, 1920, 1080);

        puts ( "Now sending payload!\n" );
        uint16_t _first_sequ = _m_session->_sequence_number;

        /* use already defined buffer lenght */
        _m_msg = rtp_msg_new ( _m_session, test_bytes, strlen(test_bytes), NULL );

        rtp_send_msg ( _m_session, _m_msg );         /* It deallocates */

        rtp_remove_resolution_marking(_m_session);

        _m_msg = rtp_msg_new ( _m_session, test_bytes, strlen(test_bytes), NULL );

        rtp_send_msg ( _m_session, _m_msg );

        printf ( "First sequence num :%d\n"
                 "Last sequence num  :%d\n\n"
                 "SSRC :%d\n\n"
                 "Packets sent: %d\n"
                 "Bytes sent:   %d\n\n"
                 "CC:           %d\n",
                 _first_sequ,
                 _m_session->_sequence_number,
                 _m_session->_ssrc,
                 _m_session->_packets_sent,
                 _m_session->_bytes_sent,
                 _m_session->_csrc[0] );



        if ( _m_session->_last_error ) {
            puts ( _m_session->_last_error );
        }
        printf ( "Payload: ( %d ) \n%s\n", strlen(test_bytes), test_bytes );

        return rtp_terminate_session(_m_session);

    } else {
        return FAILURE;
    }

    return SUCCESS;
}
