#include "test_helper.h"
#include "../../core/helper.h"
#include "../handler.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>


#define RTP_PORT 31000
#define RTP_PORT_LISTEN 31001

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
                "%d > :%d\n", i, _m_session->_csrc[i]
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
        "\tCSRC's:"
        ,
        rtp_header_get_flag_version ( _header ),
        rtp_header_get_flag_padding ( _header ),
        rtp_header_get_flag_extension ( _header ),
        rtp_header_get_flag_CSRC_count ( _header ),
        rtp_header_get_setting_payload_type ( _header ),
        rtp_header_get_setting_marker ( _header ),

        _header->_ssrc,
        _header->_sequence_number
    );

    for ( uint8_t i = 0; i < rtp_header_get_flag_CSRC_count ( _header ); i++ ) {
            printf (
                "%d > :%d\n", i, _header->_csrc[i]
            );
            }

    puts ( "\n" );
    }

/*_test_main()*/
_no_main()
    {
    arg_t* _list = parse_args ( argc, argv );

    if ( _list == NULL ) { /* failed */
            return print_help();
            }

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

    if ( find_arg_simple ( _list, "-r" ) != FAILURE ) { /* Server mode */

            IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
            LOCAL_IP.ip.i = inet_addr ( "127.0.0.1" );
            LOCAL_IP.port = RTP_PORT;
            LOCAL_IP.padding = -1;
            _m_session = init_rtp_session ( LOCAL_IP, -1 );


            status = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );
            tux_sock _socket;


            if ( status < 0 ) {
                    _m_session->_last_error = strerror ( errno );
                    puts ( _m_session->_last_error );
                    return FAILURE;
                    }

            /* -- start in recv mode, get 1 message and then analyze it -- */


            for ( int i = 0; i < 400; i++ ) { /* Recv for x seconds */
                    _m_msg = rtp_recv_msg ( _m_session );

                    /* _m_msg = rtp_session_get_message_queded ( _m_session ); DEPRECATED */
                    if ( _m_msg ) {
                            break;
                            }

                    usleep ( 10000 );
                    }

            rtp_header_t* _header = rtp_extract_header ( _m_msg->_data, _m_msg->_length );

            if ( _header ) {
                    print_header_info ( _header );
                    }

            print_session_stats ( _m_session );

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
            puts ( "Now sending payload!\n" );

            uint16_t _first_sequ = _m_session->_sequence_number;

            _m_msg = rtp_msg_new ( _m_session, test_bytes, strlen ( test_bytes ) + 1, NULL ) ; /* just don't use strlen since it's slow */
            /* use already defined buffer lenght */

            rtp_send_msg ( _m_session, _m_msg );         /* It deallocates */
            
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

            return status;
            }
    else {
            return FAILURE;
            }

    return SUCCESS;
    }
