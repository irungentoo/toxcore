#include "../handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "test_helper.h"

#define RTP_PORT 31000
#define RTP_PORT_LISTEN 31001

int print_help()
    {
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
                        "		 			  [-r ( recv mode ) ]";
    puts ( _help );
    return FAILURE;
    }

_no_main()
/*_test_main()*/
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

            /* start in recv mode */
            while ( 1 ) {
                    if ( rtp_recv_msg ( _m_session ) != FAILURE ) {
                            _m_msg = rtp_session_get_message_queded ( _m_session );

                            if ( _m_msg ) {
                                    /**/
                                    printf ( "Bytes received: %d\n", _m_session->_bytes_recv );
                                    /**/

                                    }
                            }

                    usleep ( 10000 );
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
            printf ( "Remote: %s:%d\n", ip, port );
            status = init_networking ( Ip_port[0].ip, RTP_PORT );
            _m_session = init_rtp_session ( Ip_port[0], -1 );
            puts ( "Now sending for ~5 s" );

            for ( int i = 0; i < 1500; i++ ) {
                    _m_msg = rtp_msg_new ( _m_session, test_bytes, strlen ( test_bytes ) + 1, NULL ) ;
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

