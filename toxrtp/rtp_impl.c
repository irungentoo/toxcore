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
#include "toxcore/util.h"
#include "toxcore/network.h"

/* Some defines */

#define PAYLOAD_ID_VALUE_OPUS 1
#define PAYLOAD_ID_VALUE_VP8  2

/* End of defines */

data_t LAST_SOCKET_DATA[MAX_UDP_PACKET_SIZE];

#ifdef _USE_ERRORS
#include "rtp_error_id.h"
#endif /* _USE_ERRORS */

static const uint32_t _payload_table[] = /* PAYLOAD TABLE */
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

rtp_session_t* rtp_init_session ( int max_users )
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

    _retu->_version = RTP_VERSION;   /* It's always 2 */
    _retu->_padding = 0;             /* If some additional data is needed about
                                      * the packet */
    _retu->_extension = 0;           /* If extension to header is needed */
    _retu->_cc        = 1;           /* It basically represents amount of contributors */
    _retu->_csrc      = NULL;        /* Container */
    _retu->_ssrc      = t_random ( -1 );
    _retu->_marker    = 0;
    _retu->_payload_type = 0;        /* You should specify payload type */

    /* Sequence starts at random number and goes to _MAX_SEQU_NUM */
    _retu->_sequence_number = t_random ( _MAX_SEQU_NUM );
    _retu->_last_sequence_number = _retu->_sequence_number; /* Do not touch this variable */

    _retu->_initial_time = now();    /* In seconds */
    _retu->_time_elapsed = 0;        /* In seconds */

    _retu->_ext_header = NULL;       /* When needed allocate */

    ALLOCATOR_S ( _retu->_csrc, uint32_t )
    _retu->_csrc[0] = _retu->_ssrc;  /* Set my ssrc to the list receive */

    _retu->_prefix_length = 0;
    _retu->_prefix = NULL;
    /*
     *
     */
    memset ( LAST_SOCKET_DATA, '\0', MAX_UDP_PACKET_SIZE );
    return _retu;
}

int rtp_terminate_session ( rtp_session_t* _session )
{
    if ( !_session )
        return FAILURE;

    if ( _session->_dest_list )
        DEALLOCATOR_LIST_S ( _session->_dest_list, rtp_dest_list_t )

        if ( _session->_ext_header )
            DEALLOCATOR ( _session->_ext_header )

            if ( _session->_csrc )
                DEALLOCATOR ( _session->_csrc )

                DEALLOCATOR ( _session->_prefix )
                /* And finally free session */
                DEALLOCATOR ( _session )

                return SUCCESS;
}

uint16_t rtp_get_resolution_marking_height ( rtp_ext_header_t* _header )
{
    if ( _header->_ext_type == RTP_EXT_TYPE_RESOLUTION )
        return _header->_hd_ext[_header->_ext_len - 1];
    else
        return 0;
}

uint16_t rtp_get_resolution_marking_width ( rtp_ext_header_t* _header )
{
    if ( _header->_ext_type == RTP_EXT_TYPE_RESOLUTION )
        return ( _header->_hd_ext[_header->_ext_len - 1] >> 16 );
    else
        return 0;
}

void rtp_free_msg ( rtp_session_t* _session, rtp_msg_t* _message )
{
    free ( _message->_data );

    if ( _session->_csrc != _message->_header->_csrc )
        free ( _message->_header->_csrc );
    if ( _message->_ext_header && _session->_ext_header != _message->_ext_header ) {
        free ( _message->_ext_header->_hd_ext );
        free ( _message->_ext_header );
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

int rtp_add_receiver ( rtp_session_t* _session, IP_Port* _dest )
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
    if ( !_msg  || _msg->_data == NULL || _msg->_length <= 0 ) {
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

    if ( _session->_prefix && _msg->_length + _prefix_length < MAX_UDP_PACKET_SIZE ) {
        /*t_memcpy(_send_data, _session->_prefix, _prefix_length);*/
        _send_data[0] = 70;
        _length += _prefix_length;

        t_memcpy ( _send_data + _prefix_length, _msg->_data, _length );
    } else {
        t_memcpy ( _send_data, _msg->_data, _length );
    }

    /* Set sequ number */
    if ( _session->_sequence_number == _MAX_SEQU_NUM ) {
        _session->_sequence_number = 0;
    } else {
        _session->_sequence_number++;
    }

    /* Start sending loop */
    rtp_dest_list_t* _it;
    for ( _it = _session->_dest_list; _it != NULL; _it = _it->next ) {

        _last = sendpacket ( _socket, _it->_dest, _send_data, _length );

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
    /*
        uint32_t  _bytes;
        IP_Port  _from;
        int status = receivepacket ( &_from, LAST_SOCKET_DATA, &_bytes );


        if ( status == FAILURE )  /* nothing recved */ /*
        return NULL;

    LAST_SOCKET_DATA[_bytes] = '\0';

    _session->_bytes_recv += _bytes;
    _session->_packets_recv ++;

    return rtp_msg_parse ( _session, LAST_SOCKET_DATA, _bytes ); */

    rtp_msg_t* _retu = _session->_oldest_msg;

    if ( _retu )
        _session->_oldest_msg = _retu->_next;

    if ( !_session->_oldest_msg )
        _session->_last_msg = NULL;

    return _retu;
}

rtp_msg_t* rtp_msg_new ( rtp_session_t* _session, const data_t* _data, uint32_t _length )
{
    if ( !_session )
        return NULL;

    data_t* _from_pos;
    rtp_msg_t* _retu;
    ALLOCATOR_S ( _retu, rtp_msg_t )

    /* Sets header values and copies the extension header in _retu */
    _retu->_header = rtp_build_header ( _session ); /* It allocates memory and all */
    _retu->_ext_header = _session->_ext_header;

    _length += _retu->_header->_length;

    if ( _retu->_ext_header ) {

        _length += ( 4 + _retu->_ext_header->_ext_len * 4 );
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

rtp_msg_t* rtp_msg_parse ( rtp_session_t* _session, const data_t* _data, uint32_t _length )
{
    if ( !_session )
        return NULL;

    rtp_msg_t* _retu;
    ALLOCATOR_S ( _retu, rtp_msg_t )

    _retu->_header = rtp_extract_header ( _data, _length ); /* It allocates memory and all */
    _retu->_length = _length - _retu->_header->_length;

    uint16_t _from_pos = _retu->_header->_length;

    /*
     * Check Sequence number. If this new msg has lesser number then expected drop it return
     * NULL and add stats _packet_loss into _session. RTP does not specify what you do when the packet is lost.
     * You may for example play previous packet, show black screen etc.
     */

    if ( _retu->_header->_sequence_number < _session->_last_sequence_number &&
            _retu->_header->_timestamp < _session->_current_timestamp ) {

        /* Just to check if the sequence number reset */

        _session->_packet_loss++;

        free ( _retu->_header );
        free ( _retu );

#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_PACKET_DROPED );
#endif /* _USE_ERRORS */

        return NULL; /* Drop the packet. You can check if the packet dropped by checking _packet_loss increment. */

    }

    _session->_last_sequence_number = _retu->_header->_sequence_number;
    _session->_current_timestamp = _retu->_header->_timestamp;

    if ( rtp_header_get_flag_extension ( _retu->_header ) ) {
        _retu->_ext_header = rtp_extract_ext_header ( _data + _from_pos, _length );
        _retu->_length -= ( 4 + _retu->_ext_header->_ext_len * 4 );
        _from_pos += ( 4 + _retu->_ext_header->_ext_len * 4 );
    } else {
        _retu->_ext_header = NULL;
    }

    /* Get the payload */
    _retu->_data = malloc ( sizeof ( data_t ) * _retu->_length );
    t_memcpy ( _retu->_data, _data + _from_pos, _length - _from_pos );

    _retu->_next = NULL;

    return _retu;
}


int rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height )
{
    if ( ! ( _session->_ext_header ) ) {
        ALLOCATOR_S ( _session->_ext_header, rtp_ext_header_t )
        _session->_extension = 1;
        _session->_ext_header->_ext_len = 0;
        ALLOCATOR_S ( _session->_ext_header->_hd_ext, uint32_t )
    } else {
        ADD_ALLOCATE ( _session->_ext_header->_hd_ext, _session->_ext_header->_ext_len )
    }

    _session->_ext_header->_ext_len++; /* Just add one */
    _session->_ext_header->_ext_type = RTP_EXT_TYPE_RESOLUTION;


    _session->_ext_header->_hd_ext[_session->_ext_header->_ext_len - 1] = _width << 16 | ( uint32_t ) _height;

    return SUCCESS;
}

int rtp_remove_resolution_marking ( rtp_session_t* _session )
{
    if ( _session->_extension == 0 || ! ( _session->_ext_header ) ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_PAYLOAD_INVALID );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    if ( _session->_ext_header->_ext_type != RTP_EXT_TYPE_RESOLUTION ) {
#ifdef _USE_ERRORS
        t_perror ( RTP_ERROR_INVALID_EXTERNAL_HEADER );
#endif /* _USE_ERRORS */
        return FAILURE;
    }

    DEALLOCATOR ( _session->_ext_header->_hd_ext )
    DEALLOCATOR ( _session->_ext_header )

    _session->_ext_header = NULL; /* It's very important */
    _session->_extension = 0;

    return SUCCESS;
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
