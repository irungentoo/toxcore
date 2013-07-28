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

int rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* _msg )
    {
    if ( !_session ) {
            return FAILURE;
            }

    int _last;
    unsigned long long _total = 0;

    for ( rtp_dest_list_t* _it = _session->_dest_list; _it != NULL; _it = _it->next ) {
            if ( !_msg  || _msg->_data == NULL ) {
                    _session->_last_error = "Tried to send empty message";
                    }
            else {
                    _last = sendpacket ( _it->_dest, _msg->_data, _msg->_length );

                    if ( _last < 0 ) {
                            _session->_last_error = strerror ( errno );
                            }
                    else {
                            /* Set sequ number */
                            if ( _session->_sequence_number == _MAX_SEQU_NUM ) {
                                    _session->_sequence_number = 0;
                                    }
                            else {
                                    _session->_sequence_number++;
                                    }


                            _session->_packets_sent ++;
                            _total += _last;
                            }
                    }
            }

    DEALLOCATOR_MSG ( _msg ) /* free message */
    _session->_bytes_sent += _total;
    return SUCCESS;
    }

rtp_msg_t* rtp_recv_msg ( rtp_session_t* _session )
    {
    if ( !_session ) {
            return NULL;
            }

    int32_t  _bytes;
    IP_Port  _from;
    int status = receivepacket ( &_from, LAST_SOCKET_DATA, &_bytes );

    if ( status == FAILURE ) { /* nothing recved */
            return NULL;
            }

    _session->_bytes_recv += _bytes;
    _session->_packets_recv ++;

    return rtp_msg_parse ( _session, LAST_SOCKET_DATA, _bytes, &_from );
    }

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from )
    {
    rtp_msg_t* _retu;
    ALLOCATOR_LIST_D ( _retu, rtp_msg_t, NULL )

    _retu->_header = ( rtp_header_t* ) rtp_build_header ( _session ); /* It allocates memory and all */
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

rtp_msg_t* rtp_msg_parse ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from )
    {
    rtp_msg_t* _retu;
    ALLOCATOR_LIST_D ( _retu, rtp_msg_t, NULL )

    _retu->_header = rtp_extract_header ( _data, _length ); /* It allocates memory and all */

    if ( ! ( _retu->_header ) ) {
            return NULL;
            }
    else if ( rtp_header_get_flag_CSRC_count ( _retu->_header ) == 1 ) { /* Which means initial msg */
            ADD_ALLOCATE ( _session->_csrc, uint32_t, 1 )
            _session->_cc = 2;
            _session->_csrc[1] = _retu->_header->_csrc[0];
            }
    /*
     * Check Sequence number. If this new msg has lesser number then expected drop it return
     * NULL and add stats _packet_loss into _session. RTP does not specify what you do when the packet is lost.
     * You may for example playback previous packet, show black screen etc.
     */

    else if ( _retu->_header->_sequence_number < _session->_last_sequence_number ) {
            if ( _retu->_header->_sequence_number != 0 ) { // if == 0 then it's okay
                    _session->_packet_loss++;
                    _session->_last_sequence_number = _retu->_header->_sequence_number;

                    free ( _retu->_header );
                    free ( _retu );
                    return NULL; /* Yes return NULL ( Drop the packet ) */
                    }
            }

    _session->_last_sequence_number = _retu->_header->_sequence_number;

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
