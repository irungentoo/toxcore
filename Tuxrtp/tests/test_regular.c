/*   test_regular.c
 *
 *   Tests regular RTP flow. Use this for data transport. !Red!
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

#include "../rtp_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "test_helper.h"

/*
int print_help()
    {
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
                        "                     [-r ( recv mode ) ]";
    puts ( _help );
    return FAILURE;
    }
*/
int main ( int argc, char* argv[] )
{
    int status;
    IP_Port     Ip_port;
    const char* ip;
    uint16_t    port;
    const char* test_bytes = "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789"
                             "0123456789012345678901234567890123456789012345678901234567890123456789";


    rtp_session_t* _m_session;
    rtp_msg_t*     _m_msg;
    arg_t* _list = parse_args ( argc, argv );


    if ( _list == NULL ) { /* failed */
        return print_help();
    }

    if ( find_arg_simple ( _list, "-r" ) != FAILURE ) {
        IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
        LOCAL_IP.ip.i = htonl(INADDR_ANY);

        LOCAL_IP.port = htons( RTP_PORT );
        LOCAL_IP.padding = -1;
        _m_session = rtp_init_session ( -1 ); /* You can even init it at the starting session */
        status     = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );



        if ( status < 0 ) {
            _m_session->_last_error = strerror ( errno );
            puts ( _m_session->_last_error );
            return FAILURE;
        }


        rtp_add_resolution_marking(_m_session, 100, 100);
        /* start in recv mode */
        while ( 1 ) {
            _m_msg = rtp_recv_msg ( _m_session );

            if ( _m_msg ) {
                /*
                printf ( "H: %d; W: %d\n", rtp_get_resolution_marking_width(_m_msg->_ext_header), rtp_get_resolution_marking_height(_m_msg->_ext_header) );
                /**/
                rtp_free_msg(_m_session, _m_msg);
            }

            usleep ( 10000 );
        }
    } else if ( find_arg_simple ( _list, "-s" ) != FAILURE ) {
        ip = find_arg_duble ( _list, "-d" );

        if ( ip == NULL ) {
            return FAILURE;
        }

        const char* _port = find_arg_duble ( _list, "-p" );

        if ( _port != NULL ) {
            port = atoi ( _port );
        }

        set_ip_port ( ip, port, &Ip_port );
        printf ( "Remote: %s:%d\n", ip, port );


        IP_Port REMOTE_IP;
        REMOTE_IP.ip.i = htonl(INADDR_ANY);

        status = init_networking ( REMOTE_IP.ip, RTP_PORT );


        _m_session = rtp_init_session ( -1 );
        rtp_add_receiver( _m_session, &Ip_port );
        puts ( "Now sending for ~5 s" );


        if ( status < 0 && _m_session ) {
            _m_session->_last_error = strerror ( errno );
            puts ( _m_session->_last_error );
            return FAILURE;
        }

        rtp_set_payload_type(_m_session, 106);
        rtp_add_resolution_marking(_m_session, 100, 100);

        for ( ;; ) {
            _m_msg = rtp_msg_new ( _m_session, test_bytes, 280 ) ;
            rtp_send_msg ( _m_session, _m_msg );
            usleep ( 10000 );
        }

        printf ( "Packets sent: %d\n", _m_session->_packets_sent );
        printf ( "Bytes sent:   %d\n", _m_session->_bytes_sent );

        if ( _m_session->_last_error ) {
            puts ( _m_session->_last_error );
        }

        return status;
    } else {
        return FAILURE;
    }

    return SUCCESS;
}

