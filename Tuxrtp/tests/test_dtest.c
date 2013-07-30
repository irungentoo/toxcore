/*   test_dtest.c
 *
 *   Tests durability of RTP session ( i.e. memory usage ). !Red!
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

#include "../handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>
#include <curses.h>

#include "test_helper.h"

#define RTP_PORT 31000
#define RTP_PORT_LISTEN 31001

int print_help()
    {
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
                        "		 			  [-r ( recv mode ) -i INTERVAL ( interval in seconds ) ]";
    puts ( _help );
    return FAILURE;
    }

int main(args)
    {
    int status;
    IP_Port     Ip_port[1];
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
            LOCAL_IP.ip.i = inet_addr ( "127.0.0.1" );
            LOCAL_IP.port = RTP_PORT;
            LOCAL_IP.padding = -1;
            _m_session = init_rtp_session ( LOCAL_IP, -1 ); /* You can even init it at the starting session */
            status     = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );

            tux_sock _socket;


            if ( status < 0 ) {
                    _m_session->_last_error = strerror ( errno );
                    puts ( _m_session->_last_error );
                    return FAILURE;
                    }

            const char* _interval_arg = find_arg_duble ( _list, "-i" );
            int _interval = 0;

            if ( _interval_arg != NULL ) {
                    _interval = atoi ( _interval_arg );
                    }

            /* start in recv mode */

            int _interval_counter = _interval * 100;
            while ( 1 ) {
                    _m_msg = rtp_recv_msg ( _m_session );

                    /* _m_msg = rtp_session_get_message_queded ( _m_session ); DEPRECATED */
                    if ( _m_msg ) {
                            /* ADD MSG HANDLERS HERE */
                            /**/

                            DEALLOCATOR_MSG ( _m_msg )
                            }


                    if ( _interval_counter == 0 ) {

                            printf ( "Bytes received:   %d\n"
                                     "Packets received: %d\n"
                                     "Packet loss:      %d\n"
                                     , _m_session->_bytes_recv
                                     , _m_session->_packets_recv
                                     , _m_session->_packet_loss );

                            _interval_counter = _interval * 100;

                            }

                    usleep ( 10000 );
                    _interval_counter--;
                    }
            }
    else if ( find_arg_simple ( _list, "-s" ) != FAILURE ) {
            ip = find_arg_duble ( _list, "-d" );

            if ( ip == NULL ) {
                    return FAILURE;
                    }

            const char* _port = find_arg_duble ( _list, "-p" );

            if ( _port != NULL ) {
                    port = atoi ( _port );
                    }

            set_ip_port ( ip, port, Ip_port );
            status = init_networking ( Ip_port[0].ip, RTP_PORT );
            _m_session = init_rtp_session ( Ip_port[0], -1 );
            printf ( "Now sending to remote: %s:%d ... ( press c to stop )\n", ip, port );

            for ( int _ch; _ch != 'c'; ) {
                    _m_msg = rtp_msg_new ( _m_session, test_bytes, 280, NULL ) ;
                    rtp_send_msg ( _m_session, _m_msg );
                    usleep ( 10000 );

                    }

            printf ( "Packets sent: %d\n", _m_session->_packets_sent );
            printf ( "Bytes sent:   %d\n", _m_session->_bytes_sent );

            if ( _m_session->_last_error ) {
                    puts ( _m_session->_last_error );
                    }

            return status;
            }
    else {
            return FAILURE;
            }

    return SUCCESS;
    }


