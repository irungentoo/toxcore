#include "handler.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utime.h>
#include <assert.h>

#include "../core/helper.h"

#define RTP_PORT 31000
#define RTP_PORT_LISTEN 31001

typedef struct arg_s arg_t;
struct arg_s
{
    const char* value;
    arg_t* next;
    arg_t* prev;
};

int print_help()
{
    const char* _help = " Usage: Tux_rtp_impl [-s (send mode) -d IP ( destination ) -p PORT ( dest Port )] \n"
                        "		 			  [-r ( recv mode ) ]";
    puts ( _help );
    return FAILURE;
}

arg_t* parse_args ( int argc, char* argv[] )
{
    arg_t* _list;
    if ( argc == 1 )
        {
            return NULL;
        }
    ALLOCATOR_LIST_D ( _list, arg_t, NULL )
    arg_t* it = _list;
    for ( size_t val = 0; val < argc; val ++ )
        {
            it->value = argv[val];
            if ( val < argc - 1 ) /* just about to end */
                {
                    ALLOCATOR_LIST_NEXT_D ( it, arg_t )
                }
        }
    return _list;
}

int find_arg_simple ( arg_t* _head, const char* _id )
{
    arg_t* it = _head;
    for ( int i = 1; it != NULL; it = it->next )
        {
            if ( strcmp ( _id, it->value ) == 0 )
                {
                    return i;
                }
            i++;
        }
    return FAILURE;
}

const char* find_arg_duble ( arg_t* _head, const char* _id )
{
    for ( arg_t* it = _head; it != NULL; it = it->next )
        {
            if ( strcmp ( _id, it->value ) == 0 )
                {
                    if ( it->next && it->next->value[0] != '-' ) /* exclude option */
                        {
                            return it->next->value;
                        }
                    else
                        {
                            return NULL;
                        }
                }
        }
    return NULL;
}

int main ( int argc, char* argv[] )
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
    if ( _list == NULL ) /* failed */
        {
            return print_help();
        }
    if ( find_arg_simple ( _list, "-r" ) != FAILURE )
        {
            IP_Port LOCAL_IP; /* since you need at least 1 recv-er */
            LOCAL_IP.ip.i = inet_addr ( "127.0.0.1" );
            LOCAL_IP.port = RTP_PORT;
            LOCAL_IP.padding = -1;
            status = init_networking ( LOCAL_IP.ip, RTP_PORT_LISTEN );
            tux_sock _socket;/* = init_listener_socket(RTP_PORT_LISTEN); */
            if ( status < 0 )
                {
                    _m_session->_last_error = strerror ( errno );
                    puts ( _m_session->_last_error );
                    return FAILURE;
                }
            _m_session = init_rtp_session ( LOCAL_IP, -1 );
            /* start in recv mode */
            while ( 1 )
                {
                    if ( rtp_recv_msg ( _m_session, _socket ) != FAILURE )
                        {
                            _m_msg = rtp_session_get_message_queded ( _m_session );
                            if ( _m_msg )
                                {
                                    printf ( "Bytes recved: %d\n", _m_session->_bytes_recv );
                                }
                        }
                    usleep ( 10000 );
                }
        }
    else
        if ( find_arg_simple ( _list, "-s" ) != FAILURE )
            {
                ip = find_arg_duble ( _list, "-d" );
                if ( ip == NULL )
                    {
                        return FAILURE;
                    }
                const char* _port = find_arg_duble ( _list, "-p" );
                if ( _port != NULL )
                    {
                        port = atoi ( _port );
                    }
                set_ip_port ( ip, port, Ip_port );
                printf ( "Remote: %s:%d\n", ip, port );
                status = init_networking ( Ip_port[0].ip, RTP_PORT );
                _m_session = init_rtp_session ( Ip_port[0], -1 );
                puts ( "Now sending for ~5 s" );
                for ( int i = 0; i < 500; i++ )
                    {
                        _m_msg = rtp_msg_new ( test_bytes, strlen ( test_bytes ) + 1, NULL ) ;
                        rtp_send_msg ( _m_session, _m_msg );
                        usleep ( 10000 );
                    }
                printf ( "Packets sent: %d\n", _m_session->_packets_sent );
                printf ( "Bytes sent:   %d\n", _m_session->_bytes_sent );
                if ( _m_session->_last_error )
                    {
                        puts ( _m_session->_last_error );
                    }
                return status;
            }
        else
            {
                return FAILURE;
            }
    return SUCCESS;
}
