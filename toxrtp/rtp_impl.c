/* rtp_impl.c
*
* Rtp implementation includes rtp_session_s struct which is a session identifier.
* It contains session information and it's a must for every session.
* It's best if you don't touch any variable directly but use callbacks to do so. !Red!
*
*
* Copyright (C) 2013 Tox project All Rights Reserved.
*
* This file is part of Tox.
*
* Tox is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Tox is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Tox. If not, see <http://www.gnu.org/licenses/>.
*
*/
#include "rtp_impl.h"
#include "rtp_message.h"
#include "rtp_helper.h"
#include <assert.h>
#include "rtp_allocator.h"
#include "util.h"
#include "network.h"

/* Some defines */

#define PAYLOAD_ID_VALUE_OPUS 1
#define PAYLOAD_ID_VALUE_VP8 2

#define size_32 4
/* End of defines */

#ifdef _USE_ERRORS
#include "rtp_error_id.h"
#endif /* _USE_ERRORS */

static const uint32_t _payload_table[] = /* PAYLOAD TABLE */
{
    8000, 8000, 8000, 8000, 8000, 8000, 16000, 8000, 8000, 8000, /* 0-9 */
    44100, 44100, 0, 0, 90000, 8000, 11025, 22050, 0, 0, /* 10-19 */
    0, 0, 0, 0, 0, 90000, 90000, 0, 90000, 0, /* 20-29 */
    0, 90000, 90000, 90000, 90000, 0, 0, 0, 0, 0, /* 30-39 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 40-49 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 50-59 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 60-69 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 70-79 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 80-89 */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_OPUS, 0, 0, 0, /* 90-99 */
    0, 0, 0, 0, 0, 0, PAYLOAD_ID_VALUE_VP8, 0, 0, 0, /* 100-109 */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 110-119 */
    0, 0, 0, 0, 0, 0, 0, 0 /* 120-127 */
};

/* Current compatibility solution */
int m_sendpacket(int sock, tox_IP_Port ip_port, uint8_t *data, uint32_t length)
{
    IP_Port _convert;

    _convert.ip.i = ip_port.ip.i;
    _convert.port = ip_port.port;

    return sendpacket(sock, _convert, data, length);
}

rtp_session_t* rtp_init_session ( int max_users, int _multi_session )
{
#ifdef _USE_ERRORS
    REGISTER_RTP_ERRORS
#endif /* _USE_ERRORS */

    rtp_session_t* _retu;
    ALLOCATOR_S ( _retu, rtp_session_t )

    _retu->_dest_list = _retu->_last_user = NULL;

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
    _retu->_padding = 0; /* If some additional data is needed about
* the packet */
    _retu->_extension = 0; /* If extension to header is needed */
    _retu->_cc = 1; /* It basically represents amount of contributors */
    _retu->_csrc = NULL; /* Container */
    _retu->_ssrc = t_random ( -1 );
    _retu->_marker = 0;
    _retu->_payload_type = 0; /* You should specify payload type */

    /* Sequence starts at random number and goes to _MAX_SEQU_NUM */
    _retu->_sequence_number = t_random ( _MAX_SEQU_NUM );
    _retu->_last_sequence_number = _retu->_sequence_number; /* Do not touch this variable */

    _retu->_initial_time = _time; /* In seconds */
    assert(_retu->_initial_time);
    _retu->_time_elapsed = 0; /* In seconds */

    _retu->_ext_header = NULL; /* When needed allocate */
    _retu->_exthdr_framerate = -1;
    _retu->_exthdr_resolution = -1;

    ALLOCATOR_S ( _retu->_csrc, uint32_t )
    _retu->_csrc[0] = _retu->_ssrc; /* Set my ssrc to the list receive */

    _retu->_prefix_length = 0;
    _retu->_prefix = NULL;

    _retu->_multi_session = _multi_session;

    /* Initial */
    _retu->_current_framerate = 0;


    _retu->_oldest_msg = _retu->_last_msg = NULL;
    /*
*
*/
    return _retu;
}

int rtp_terminate_session ( rtp_session_t* _session )
{
    if ( !_session )
        return FAILURE;

    if ( _session->_dest_list )
        DEALLOCATOR_LIST_S ( _session->_dest_list, rtp_dest_list_t );

    if ( _session->_ext_header )
        DEALLOCATOR ( _session->_ext_header );

    if ( _session->_csrc )
        DEALLOCATOR ( _session->_csrc );

    if ( _session->_prefix )
        DEALLOCATOR ( _session->_prefix );
                /* And finally free session */
    DEALLOCATOR ( _session );

    return SUCCESS;
}

uint16_t rtp_get_resolution_marking_height ( rtp_ext_header_t* _header, uint32_t _position )
{
    if ( _header->_ext_type & RTP_EXT_TYPE_RESOLUTION )
        return _header->_hd_ext[_position];
    else
        return 0;
}

uint16_t rtp_get_resolution_marking_width ( rtp_ext_header_t* _header, uint32_t _position )
{
    if ( _header->_ext_type & RTP_EXT_TYPE_RESOLUTION )
        return ( _header->_hd_ext[_position] >> 16 );
    else
        return 0;
}

void rtp_free_msg ( rtp_session_t* _session, rtp_msg_t* _message )
{
    free ( _message->_data );

    if ( !_session ){
        free ( _message->_header->_csrc );
        if ( _message->_ext_header ){
            free ( _message->_ext_header->_hd_ext );
            free ( _message->_ext_header );
        }
    } else {
        if ( _session->_csrc != _message->_header->_csrc )
            free ( _message->_header->_csrc );
        if ( _message->_ext_header && _session->_ext_header != _message->_ext_header ) {
            free ( _message->_ext_header->_hd_ext );
            free ( _message->_ext_header );
        }
    }

    free ( _message->_header );
    free ( _message );
}

rtp_header_t* rtp_build_header ( rtp_session_t* _session )
{
    rtp_header_t* _retu;
    _retu = malloc ( sizeof * _retu );

    rtp_header_add_flag_version ( _retu, _session->_version );
    rtp_header_add_flag_padding ( _retu, _session->_padding );
    rtp_header_add_flag_extension ( _retu, _session->_extension );
    rtp_header_add_flag_CSRC_count ( _retu, _session->_cc );
    rtp_header_add_setting_marker ( _retu, _session->_marker );
    rtp_header_add_setting_payload ( _retu, _session->_payload_type );

    _retu->_sequence_number = _session->_sequence_number;
    _session->_time_elapsed = _time - _session->_initial_time;
    _retu->_timestamp = _time;
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

    _retu->_length = _MIN_HEADER_LENGTH + ( _session->_cc * size_32 );

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

int rtp_add_receiver ( rtp_session_t* _session, tox_IP_Port* _dest )
{
    if ( !_session )
        return FAILURE;

    rtp_dest_list_t* _new_user;
    ALLOCATOR_LIST_S ( _new_user, rtp_dest_list_t, NULL )

    _new_user->_dest = *_dest;

    if ( _session->_last_user == NULL ) { /* New member */
        _session->_dest_list = _session->_last_user = _new_user;

    } else { /* Append */
        _session->_last_user->next = _new_user;
        _session->_last_user = _new_user;
    }

    return SUCCESS;
}

int rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* _msg, int _socket )
{
    if ( !_msg || _msg->_data == NULL || _msg->_length <= 0 ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_EMPTY_MESSAGE );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    int _last;
    unsigned long long _total = 0;

    size_t _length = _msg->_length;
    uint8_t _send_data [ MAX_UDP_PACKET_SIZE ];

    uint16_t _prefix_length = _session->_prefix_length;

    if ( _session->_prefix && _length + _prefix_length < MAX_UDP_PACKET_SIZE ) {
        /*t_memcpy(_send_data, _session->_prefix, _prefix_length);*/
        _send_data[0] = 70;
        t_memcpy ( _send_data + _prefix_length, _msg->_data, _length - 1 );
    } else {
        t_memcpy ( _send_data, _msg->_data, _length );
    }

    /* Set sequ number */
    if ( _session->_sequence_number >= _MAX_SEQU_NUM ) {
        _session->_sequence_number = 0;
    } else {
        _session->_sequence_number++;
    }

    /* Start sending loop */
    rtp_dest_list_t* _it;
    for ( _it = _session->_dest_list; _it != NULL; _it = _it->next ) {

        _last = m_sendpacket ( _socket, _it->_dest, _send_data, _length );

        if ( _last < 0 ) {
#ifdef _USE_ERRORS
            t_perror ( RTP_ERROR_STD_SEND_FAILURE );
#endif /* _USE_ERRORS */
        } else {
            _session->_packets_sent ++;
            _total += _last;
        }

    }

    rtp_free_msg ( _session, _msg );
    _session->_bytes_sent += _total;
    return SUCCESS;
}

rtp_msg_t* rtp_recv_msg ( rtp_session_t* _session )
{
    if ( !_session )
        return NULL;

    rtp_msg_t* _retu = _session->_oldest_msg;

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    return _retu;
}

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length )
{
    if ( !_session )
        return NULL;

    uint8_t* _from_pos;
    rtp_msg_t* _retu;
    ALLOCATOR_S ( _retu, rtp_msg_t )

    /* Sets header values and copies the extension header in _retu */
    _retu->_header = rtp_build_header ( _session ); /* It allocates memory and all */
    _retu->_ext_header = _session->_ext_header;

    _length += _retu->_header->_length;

    if ( _retu->_ext_header ) {

        _length += ( _MIN_EXT_HEADER_LENGTH + _retu->_ext_header->_ext_len * size_32 );
        /* Allocate Memory for _retu->_data */
        _retu->_data = malloc ( sizeof _retu->_data * _length );

        /*
* Parses header into _retu->_data starting from 0
* Will need to set this _from to 1 since the 0 byte
* Is used by the messenger to determine that this is rtp.
*/
        _from_pos = rtp_add_header ( _retu->_header, _retu->_data );
        _from_pos = rtp_add_extention_header ( _retu->_ext_header, _from_pos + 1 );
    } else {
        /* Allocate Memory for _retu->_data */
        _retu->_data = malloc ( sizeof _retu->_data * _length );

        /*
* Parses header into _retu->_data starting from 0
* Will need to set this _from to 1 since the 0 byte
* Is used by the messenger to determine that this is rtp.
*/
        _from_pos = rtp_add_header ( _retu->_header, _retu->_data );
    }

    /*
* Parses the extension header into the message
* Of course if any
*/

    /* Appends _data on to _retu->_data */
    t_memcpy ( _from_pos + 1, _data, _length );

    _retu->_length = _length;

    _retu->_next = NULL;

    return _retu;
}

rtp_msg_t* rtp_msg_parse ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length )
{
    rtp_msg_t* _retu;
    ALLOCATOR_S ( _retu, rtp_msg_t )

    _retu->_header = rtp_extract_header ( _data, _length ); /* It allocates memory and all */

    if ( !_retu->_header ){
        DEALLOCATOR(_retu)
        return NULL;
    }

    _retu->_length = _length - _retu->_header->_length;

    uint16_t _from_pos = _retu->_header->_length;


    if ( rtp_header_get_flag_extension ( _retu->_header ) ) {
        _retu->_ext_header = rtp_extract_ext_header ( _data + _from_pos, _length );
        if ( _retu->_ext_header ){
            _retu->_length -= ( _MIN_EXT_HEADER_LENGTH + _retu->_ext_header->_ext_len * size_32 );
            _from_pos += ( _MIN_EXT_HEADER_LENGTH + _retu->_ext_header->_ext_len * size_32 );
        } else {
            DEALLOCATOR(_retu->_ext_header);
            DEALLOCATOR(_retu->_header);
            DEALLOCATOR(_retu);
            return NULL;
        }
    } else {
        _retu->_ext_header = NULL;
    }

    /* Get the payload */
    _retu->_data = malloc ( sizeof ( uint8_t ) * _retu->_length );
    t_memcpy ( _retu->_data, _data + _from_pos, _length - _from_pos );

    _retu->_next = NULL;


    if ( _session && !_session->_multi_session && rtp_check_late_message(_session, _retu) < 0 ){
        rtp_register_msg(_session, _retu);
    }

    return _retu;
}

int rtp_check_late_message (rtp_session_t* _session, rtp_msg_t* _msg)
{
    /*
* Check Sequence number. If this new msg has lesser number then the _session->_last_sequence_number
* it shows that the message came in late
*/
    if ( _msg->_header->_sequence_number < _session->_last_sequence_number &&
         _msg->_header->_timestamp < _session->_current_timestamp
       ) {
        return SUCCESS; /* Drop the packet. You can check if the packet dropped by checking _packet_loss increment. */
    }
    return FAILURE;
}

void rtp_register_msg ( rtp_session_t* _session, rtp_msg_t* _msg )
{
    _session->_last_sequence_number = _msg->_header->_sequence_number;
    _session->_current_timestamp = _msg->_header->_timestamp;
}


int rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height )
{
    if ( !_session )
        return FAILURE;

    rtp_ext_header_t* _ext_header = _session->_ext_header;
    _session->_exthdr_resolution = 0;

    if ( ! ( _ext_header ) ) {
        ALLOCATOR_S ( _session->_ext_header, rtp_ext_header_t )
        _session->_extension = 1;
        _session->_ext_header->_ext_len = 1;
        _ext_header = _session->_ext_header;
        ALLOCATOR_S ( _session->_ext_header->_hd_ext, uint32_t )
    } else { /* If there is need for more headers this will be needed to change */
        if ( !(_ext_header->_ext_type & RTP_EXT_TYPE_RESOLUTION) ){
            uint32_t _exthdr_framerate = _ext_header->_hd_ext[_session->_exthdr_framerate];
            /* it's position is at 2nd place by default */
            _session->_exthdr_framerate ++;

            /* Allocate the value */
            ADD_ALLOCATE ( _ext_header->_hd_ext, _ext_header->_ext_len )

            /* Update length */
            _ext_header->_ext_len++;

            /* Reset other values */
            _ext_header->_hd_ext[_session->_exthdr_framerate] = _exthdr_framerate;
        }
    }

    /* Add flag */
    _ext_header->_ext_type |= RTP_EXT_TYPE_RESOLUTION;

    _ext_header->_hd_ext[_session->_exthdr_resolution] = _width << 16 | ( uint32_t ) _height;

    return SUCCESS;
}

int rtp_remove_resolution_marking ( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || ! ( _session->_ext_header ) ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_INVALID_EXTERNAL_HEADER );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    if ( !( _session->_ext_header->_ext_type & RTP_EXT_TYPE_RESOLUTION ) ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_INVALID_EXTERNAL_HEADER );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    _session->_ext_header->_ext_type &= ~RTP_EXT_TYPE_RESOLUTION; /* Remove the flag */
    _session->_exthdr_resolution = -1; /* Remove identifier */

    /* Check if extension is empty */
    if ( _session->_ext_header->_ext_type == 0 ){

        DEALLOCATOR ( _session->_ext_header->_hd_ext )
        DEALLOCATOR ( _session->_ext_header )

        _session->_ext_header = NULL; /* It's very important */
        _session->_extension = 0;

    } else {
        _session->_ext_header->_ext_len --;

        /* this will also be needed to change if there are more than 2 headers */
        if ( _session->_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE ){
            memcpy(_session->_ext_header->_hd_ext + 1, _session->_ext_header->_hd_ext, _session->_ext_header->_ext_len);
            _session->_exthdr_framerate = 0;
            SET_ALLOCATE(_session->_ext_header->_hd_ext, _session->_ext_header->_ext_len);
        }
    }

    return SUCCESS;
}

int rtp_add_framerate_marking ( rtp_session_t* _session, uint32_t _value )
{
    if ( !_session )
        return FAILURE;

    rtp_ext_header_t* _ext_header = _session->_ext_header;
    _session->_exthdr_framerate = 0;

    if ( ! ( _ext_header ) ) {
        ALLOCATOR_S ( _session->_ext_header, rtp_ext_header_t )
        _session->_extension = 1;
        _session->_ext_header->_ext_len = 1;
        _ext_header = _session->_ext_header;
        ALLOCATOR_S ( _session->_ext_header->_hd_ext, uint32_t )
    } else { /* If there is need for more headers this will be needed to change */
        if ( !(_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE) ){
            /* it's position is at 2nd place by default */
            _session->_exthdr_framerate ++;

            /* Allocate the value */
            ADD_ALLOCATE ( _ext_header->_hd_ext, _ext_header->_ext_len )

            /* Update length */
            _ext_header->_ext_len++;
        }
    }

    /* Add flag */
    _ext_header->_ext_type |= RTP_EXT_TYPE_FRAMERATE;

    _ext_header->_hd_ext[_session->_exthdr_framerate] = _value;

    return SUCCESS;
}


int rtp_remove_framerate_marking ( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || ! ( _session->_ext_header ) ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_INVALID_EXTERNAL_HEADER );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    if ( !( _session->_ext_header->_ext_type & RTP_EXT_TYPE_FRAMERATE ) ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_INVALID_EXTERNAL_HEADER );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    _session->_ext_header->_ext_type &= ~RTP_EXT_TYPE_FRAMERATE; /* Remove the flag */
    _session->_exthdr_framerate = -1; /* Remove identifier */
    _session->_ext_header->_ext_len --;

    /* Check if extension is empty */
    if ( _session->_ext_header->_ext_type == 0 ){

        DEALLOCATOR ( _session->_ext_header->_hd_ext )
        DEALLOCATOR ( _session->_ext_header )

        _session->_ext_header = NULL; /* It's very important */
        _session->_extension = 0;

    } else if ( !_session->_ext_header->_ext_len ) {

        /* this will also be needed to change if there are more than 2 headers */
        SET_ALLOCATE(_session->_ext_header->_hd_ext, _session->_ext_header->_ext_len);

    }

    return SUCCESS;
}

uint32_t rtp_get_framerate_marking ( rtp_ext_header_t* _header )
{
    if ( _header->_ext_len == 1 ){
        return _header->_hd_ext[0];
    } else {
        return _header->_hd_ext[1];
    }
}

int rtp_set_prefix ( rtp_session_t* _session, uint8_t* _prefix, uint16_t _prefix_length )
{
    if ( !_session )
        return FAILURE;

    if ( _session->_prefix ) {
        free ( _session->_prefix );
    }

    _session->_prefix = malloc ( ( sizeof * _session->_prefix ) * _prefix_length );
    t_memcpy ( _session->_prefix, _prefix, _prefix_length );
    _session->_prefix_length = _prefix_length;

    return SUCCESS;
}