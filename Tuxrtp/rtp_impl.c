/*   rtp_impl.h
 *
 *   Rtp implementation includes rtp_session_s struct which is a session identifier.
 *   It contains session information and it's a must for every session.
 *   It's best if you don't touch any variable directly but use callbacks to do so. !Red!
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
#include "rtp_impl.h"
#include <assert.h>
#include "rtp_allocator.h"

/* Some defines */

#define PAYLOAD_ID_VALUE_OPUS 1
#define PAYLOAD_ID_VALUE_VP8  2

/* End of defines */

uint32_t _payload_table[] = /* PAYLOAD TABLE */
{
    8000, 8000, 8000, 8000, 8000, 8000, 16000, 8000, 8000, 8000,    /*    0-9    */
    44100, 44100, 0, 0, 90000, 8000, 11025, 22050, 0, 0,            /*   10-19   */
    0, 0, 0, 0, 0, 90000, 90000, 0, 90000, 0,                       /*   20-29   */
    0, 90000, 90000, 90000, 90000, 0, 0, 0, 0, 0,                   /*   30-39   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   40-49   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   50-59   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   60-69   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   70-79   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*   80-89   */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_OPUS, 0, 0, 0,               /*   90-99   */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_VP8, 0, 0, 0,                /*  100-109  */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                   /*  110-119  */
    0, 0, 0, 0, 0, 0, 0, 0                                          /*  120-127  */
};

rtp_session_t* rtp_init_session ( IP_Port _dest, int max_users )
{
    rtp_session_t* _retu;
    ALLOCATOR_S ( _retu, rtp_session_t )
    ALLOCATOR_LIST_S ( _retu->_dest_list, rtp_dest_list_t, NULL )

    _retu->_last_user = _retu->_dest_list; /* set tail */
    _retu->_dest_list->_dest = _dest;
    _retu->_max_users = max_users;
    _retu->_packets_recv = 0;
    _retu->_packets_sent = 0;
    _retu->_bytes_sent = 0;
    _retu->_bytes_recv = 0;
    _retu->_last_error = NULL;
    _retu->_packet_loss = 0;

    /*
     * SET HEADER FIELDS
     */

    _retu->_version = RTP_VERSION; /* It's always 2 */
    _retu->_padding = 0;             /* If some additional data is needed about
                                      * the packet */
    _retu->_extension = 0;           /* If extension to header is needed */
    _retu->_cc        = 1;           /* It basically represents amount of contributors */
    _retu->_csrc      = NULL;        /* Container */
    _retu->_ssrc      = get_random_number ( -1 );
    _retu->_marker    = 0;
    _retu->_payload_type = 0;        /* You should specify payload type */

    /* Sequence starts at random number and goes to _MAX_SEQU_NUM */
    _retu->_sequence_number = get_random_number ( _MAX_SEQU_NUM );
    _retu->_last_sequence_number = _retu->_sequence_number; /* Do not touch this variable */

    _retu->_initial_time = now();    /* In seconds */
    _retu->_time_elapsed = 0;        /* In seconds */

    _retu->_ext_header = NULL;       /* When needed allocate */

    ALLOCATOR_S ( _retu->_csrc, uint32_t )
    _retu->_csrc[0] = _retu->_ssrc;  /* Set my ssrc to the list receive */
    /*
     *
     */
    memset ( LAST_SOCKET_DATA, '\0', MAX_UDP_PACKET_SIZE );
    return _retu;
}

int rtp_terminate_session(rtp_session_t* _session)
{
    if ( !_session )
        return FAILURE;

    if ( _session->_dest_list )
        DEALLOCATOR_LIST_S(_session->_dest_list, rtp_dest_list_t)

    if ( _session->_last_error )
        DEALLOCATOR(_session->_last_error)

    if ( _session->_ext_header )
        DEALLOCATOR(_session->_ext_header)

    if ( _session->_csrc )
        DEALLOCATOR(_session->_csrc)


    /* And finally free session */
    DEALLOCATOR(_session)

    return SUCCESS;
}

int rtp_handlepacket(uint8_t * packet, uint32_t length, IP_Port source)
{
    switch ( packet[0] )
    {
    case RTP_PACKET_ID:
        return SUCCESS;
    }
}

uint16_t rtp_get_resolution_marking_height(rtp_ext_header_t* _header)
{
    if ( _header->_ext_type == RTP_EXT_TYPE_RESOLUTION )
        return _header->_hd_ext[_header->_ext_len - 1];
    else
        return 0;
}

uint16_t rtp_get_resolution_marking_width(rtp_ext_header_t* _header)
{
    if ( _header->_ext_type == RTP_EXT_TYPE_RESOLUTION )
        return ( _header->_hd_ext[_header->_ext_len - 1] >> 16 );
    else
        return 0;
}

void rtp_free_msg(rtp_session_t* _session, rtp_msg_t* _message)
{
    free(_message->_data);

    if ( _session->_csrc != _message->_header->_csrc )
        free(_message->_header->_csrc);
    if ( _session->_ext_header != _message->_ext_header){
        free(_message->_ext_header->_hd_ext);
        free(_message->_ext_header);
    }

    free(_message->_header);
    free(_message);
}

rtp_header_t* rtp_build_header ( rtp_session_t* _session )
{
    rtp_header_t* _retu;
    _retu = ( rtp_header_t* ) malloc ( sizeof ( rtp_header_t ) );

    rtp_header_add_flag_version ( _retu, _session->_version );
    rtp_header_add_flag_padding ( _retu, _session->_padding );
    rtp_header_add_flag_extension ( _retu, _session->_extension );
    rtp_header_add_flag_CSRC_count ( _retu, _session->_cc );
    rtp_header_add_setting_marker ( _retu, _session->_marker );
    rtp_header_add_setting_payload ( _retu, _session->_payload_type );

    _retu->_sequence_number = _session->_sequence_number;
    _session->_time_elapsed = now() - _session->_initial_time;
    _retu->_timestamp = _session->_initial_time + _session->_time_elapsed; /* It's equivalent of now() */
    _retu->_ssrc = _session->_ssrc;

    if ( _session->_cc > 0 ) {
        ALLOCATOR ( _retu->_csrc, uint32_t, _session->_cc )

        int i;

        for ( i = 0; i < _session->_cc; i++ ) {
            _retu->_csrc[i] = _session->_csrc[i];
        }
    } else {
        _retu->_csrc = NULL;
    }

    _retu->_length = 8 + ( _session->_cc * 4 );

    return _retu;
}

void rtp_set_payload_type ( rtp_session_t* _session, uint8_t _payload_value )
{
    _session->_payload_type = _payload_value;
}
uint32_t rtp_get_payload_type ( rtp_session_t* _session )
{
    return _payload_table[_session->_payload_type];
}



int rtp_add_user ( rtp_session_t* _session, IP_Port _dest )
{
    rtp_dest_list_t* _new_user;
    ALLOCATOR_LIST_S ( _new_user, rtp_dest_list_t, NULL )
    _session->_last_user->next = _new_user;
    _session->_last_user = _new_user;
    return SUCCESS;
}

int rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* _msg )
{
    int _last;
    unsigned long long _total = 0;


    rtp_dest_list_t* _it;
    for ( _it = _session->_dest_list; _it != NULL; _it = _it->next ) {

        if ( !_msg  || _msg->_data == NULL ) {
            _session->_last_error = "Tried to send empty message";
        } else {
            _last = sendpacket ( _it->_dest, _msg->_data, _msg->_length );

            if ( _last < 0 ) {
                _session->_last_error = strerror ( errno );
            } else {
                /* Set sequ number */
                if ( _session->_sequence_number == _MAX_SEQU_NUM ) {
                    _session->_sequence_number = 0;
                } else {
                    _session->_sequence_number++;
				}


                _session->_packets_sent ++;
                _total += _last;
            }
        }

    }

    rtp_free_msg(_session, _msg);
    _session->_bytes_sent += _total;
    return SUCCESS;
}

rtp_msg_t* rtp_recv_msg ( rtp_session_t* _session )
{
    int32_t  _bytes;
    IP_Port  _from;
    int status = receivepacket ( &_from, LAST_SOCKET_DATA, &_bytes );

    if ( status == FAILURE )  /* nothing recved */
        return NULL;


    LAST_SOCKET_DATA[_bytes] = '\0';

    _session->_bytes_recv += _bytes;
    _session->_packets_recv ++;

    return rtp_msg_parse ( _session, LAST_SOCKET_DATA, _bytes, &_from );
}

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from )
{
    rtp_msg_t* _retu;
    ALLOCATOR_S ( _retu, rtp_msg_t )

    /* Sets header values and copies the extension header in _retu */
    _retu->_header = ( rtp_header_t* ) rtp_build_header ( _session ); /* It allocates memory and all */
    _retu->_ext_header = _session->_ext_header;

    _length += _retu->_header->_length;

    /* Allocate Memory for _retu->_data */
    _retu->_data = ( uint8_t* ) malloc ( sizeof ( uint8_t ) * _length );

    /*
     * Parses header into _retu->_data starting from 0
     * Will need to set this _from to 1 since the 0 byte
     * Is used by the messenger to determine that this is rtp.
     */
    uint16_t _from_pos = rtp_add_header ( _retu->_header, _retu->_data, 0, _length );

    /*
     * Parses the extension header into the message
     * Of course if there is any
     */

    if ( _retu->_ext_header ){

        _length += ( 4 + _retu->_ext_header->_ext_len * 4 ) - 1;
        SET_ALLOCATE(_retu->_data, uint8_t, _length )

        _from_pos = rtp_add_extention_header( _retu->_ext_header, _retu->_data, _from_pos - 1, _length );
    }

    /* Appends _data on to _retu->_data */
    memadd ( _retu->_data, _from_pos, _data, _length);

    _retu->_length = _length;

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
    ALLOCATOR_S ( _retu, rtp_msg_t )

    _retu->_header = rtp_extract_header ( _data, 0, _length ); /* It allocates memory and all */

    if ( !_retu->_header )
        return NULL;


    _retu->_length = _length - _retu->_header->_length;

    uint16_t _from_pos = _retu->_header->_length;

 /*
    if ( _session->_packets_recv == 0 ) {
        ADD_ALLOCATE ( _session->_csrc, uint32_t, 1 )
        _session->_cc = 2;
        _session->_csrc[1] = _retu->_header->_csrc[0];
        _retu->_header->_length += 4;
    }
  */
    /*
     * Check Sequence number. If this new msg has lesser number then expected drop it return
     * NULL and add stats _packet_loss into _session. RTP does not specify what you do when the packet is lost.
     * You may for example play previous packet, show black screen etc.
     */

    if ( _retu->_header->_sequence_number < _session->_last_sequence_number ) {
        if ( _retu->_header->_timestamp < _session->_current_timestamp ) {
            /* Just to check if the sequence number reset */

            _session->_packet_loss++;

            free ( _retu->_header );
            free ( _retu );

            return NULL; /* Drop the packet. You can check if the packet dropped by checking _packet_loss increment. */
        }
    }

    _session->_last_sequence_number = _retu->_header->_sequence_number;
    _session->_current_timestamp = _retu->_header->_timestamp;

    if ( rtp_header_get_flag_extension(_retu->_header) ){
        _retu->_ext_header = rtp_extract_ext_header(_data, _from_pos - 1, _length);
        _retu->_length -= ( 4 + _retu->_ext_header->_ext_len * 4 ) - 1;
        _from_pos += ( 4 + _retu->_ext_header->_ext_len * 4 ) - 1;
    }
    else {
        _retu->_ext_header = NULL;
    }

    /* Get the payload */
    _retu->_data = malloc ( sizeof ( uint8_t ) * _retu->_length );
    memcpy_from ( _retu->_data, _from_pos, _data, _length);


    if ( _from ) { /* Remove this is not need */
        _retu->_from.ip = _from->ip;
        _retu->_from.port = _from->port;
        _retu->_from.padding = _from->padding;
    }

    return _retu;
}


int rtp_add_resolution_marking( rtp_session_t* _session, uint16_t _width, uint16_t _height )
{
    if ( !(_session->_ext_header) ){
        ALLOCATOR_S(_session->_ext_header, rtp_ext_header_t)
        _session->_extension = 1;
        _session->_ext_header->_ext_len = 0;
        ALLOCATOR_S(_session->_ext_header->_hd_ext, uint32_t)
    }
    else ADD_ALLOCATE ( _session->_ext_header->_hd_ext, uint32_t, _session->_ext_header->_ext_len )

    _session->_ext_header->_ext_len++; /* Just add one */
    _session->_ext_header->_ext_type = RTP_EXT_TYPE_RESOLUTION;


    _session->_ext_header->_hd_ext[_session->_ext_header->_ext_len - 1] = _width << 16 | ( uint32_t ) _height;

    return SUCCESS;
}

int rtp_remove_resolution_marking( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || !(_session->_ext_header) )
        return FAILURE;

    if ( _session->_ext_header->_ext_type != RTP_EXT_TYPE_RESOLUTION )
        return FAILURE;

    DEALLOCATOR(_session->_ext_header->_hd_ext)
    DEALLOCATOR(_session->_ext_header)

    _session->_ext_header = NULL; /* It's very important */
    _session->_extension = 0;

    return SUCCESS;
}
