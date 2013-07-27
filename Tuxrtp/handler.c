#include "handler.h"
#include <assert.h>
/* Using lossless UDP with RTP is in my opinion */

int rtp_add_user ( rtp_session_t* _session, IP_Port _dest )
    {
    if ( !_session ) {
            return FAILURE;
            }

    rtp_dest_list_t* _new_user;
    ALLOCATOR_LIST_S ( _new_user, rtp_dest_list_t, NULL )
    _session->_last_user->next = _new_user;
    _session->_last_user = _new_user;
    return SUCCESS;
    }

int rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* msg )
    {
    if ( !_session ) {
            return FAILURE;
            }

    int _last;
    unsigned long long _total = 0;

    for ( rtp_dest_list_t* _it = _session->_dest_list; _it != NULL; _it = _it->next ) {
            if ( !msg  || msg->_data == NULL ) {
                    _session->_last_error = "Tried to send empty message";
                    }
            else {
                    _last = sendpacket ( _it->_dest, msg->_data, msg->_length );

                    if ( _last < 0 ) {
                            _session->_last_error = strerror ( errno );
                            }
                    else {
                            _session->_packets_sent ++;
                            _total += _last;
                            }
                    }
            }

    DEALLOCATOR ( msg ) /* free message */
    _session->_bytes_sent += _total;
    return SUCCESS;
    }

int rtp_recv_msg ( rtp_session_t* _session )
    {
    if ( !_session ) {
            return FAILURE;
            }

    int32_t  _bytes;
    IP_Port  _from;
    int status = receivepacket ( &_from, LAST_SOCKET_DATA, &_bytes );

    if ( status == FAILURE ) { /* nothing recved */
            return status;
            }

    _session->_bytes_recv += _bytes;
    _session->_packets_recv ++;

    rtp_msg_t* _msg = rtp_msg_new ( _session, LAST_SOCKET_DATA, _bytes, &_from );

    if ( !_session->_messages ) {
            _session->_messages = _msg;
            _session->_last_msg = _msg;
            }
    else {
            _msg->prev = _session->_last_msg;
            _session->_last_msg->next = _msg;
            _session->_last_msg = _msg;
            }

    return status;
    }

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from )
    {
    rtp_msg_t* _retu;
    ALLOCATOR_LIST_D ( _retu, rtp_msg_t, NULL )

    _retu->_header = (rtp_header_t*)rtp_build_header ( _session ); /* It allocates memory and all */
    _length += _retu->_header->_length;

    _retu->_data = ( uint8_t* ) malloc ( sizeof ( uint8_t ) * _length );

    /*memcpy ( _retu->_data, _data, _length ); */
    rtp_add_header ( _retu->_header, _retu->_data, _length - _retu->_header->_length );
    memadd ( _retu->_data, _retu->_header->_length, _data, _length );

    _retu->_length = _length;

    _retu->_ext_header = NULL; /* we don't need it for now */


    if ( _from ) {
            _retu->_from.ip = _from->ip;
            _retu->_from.port = _from->port;
            _retu->_from.padding = _from->padding;
            }

    return _retu;
    }
