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

    _retu->_last_user = _retu->_dest_list; // set tail
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
    _retu->_sequence_number = get_random_number ( _MAX_SEQU_NUM );
    _retu->_last_sequence_number = 0;/* Do not touch this variable */
    /* Sequence starts at random number and goes to _MAX_SEQU_NUM */
    _retu->_initial_time = 0;        /* In seconds */
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

int rtp_add_resolution_marking( rtp_session_t* _session, uint16_t _width, uint16_t _height )
{
    if ( !_session )
        return FAILURE;

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
    if ( !_session || _session->_extension == 0 || !(_session->_ext_header) )
        return FAILURE;

    if ( _session->_ext_header->_ext_type != RTP_EXT_TYPE_RESOLUTION )
        return FAILURE;

    DEALLOCATOR(_session->_ext_header->_hd_ext)
    DEALLOCATOR(_session->_ext_header)

    _session->_ext_header = NULL; /* It's very important */
    _session->_extension = 0;

    return SUCCESS;
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

rtp_header_t* rtp_build_header ( rtp_session_t* _session )
{
    if ( !_session ) {
        return NULL;
    }

    rtp_header_t* _retu;
    _retu = ( rtp_header_t* ) malloc ( sizeof ( rtp_header_t ) );

    rtp_header_add_flag_version ( _retu, _session->_version );
    rtp_header_add_flag_padding ( _retu, _session->_padding );
    rtp_header_add_flag_extension ( _retu, _session->_extension );
    rtp_header_add_flag_CSRC_count ( _retu, _session->_cc );
    rtp_header_add_setting_marker ( _retu, _session->_marker );
    rtp_header_add_setting_payload ( _retu, _session->_payload_type );

    _retu->_sequence_number = _session->_sequence_number;
    _retu->_timestamp = _session->_initial_time + _session->_time_elapsed;
    _retu->_ssrc = _session->_ssrc;

    if ( _session->_cc > 0 ) {
        ALLOCATOR ( _retu->_csrc, uint32_t, _session->_cc )

        for ( int i = 0; i < _session->_cc; i++ ) {
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
