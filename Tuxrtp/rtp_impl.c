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

rtp_session_t* init_rtp_session ( IP_Port _dest, int max_users )
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

    _retu->_version = _RTP_VERSION_; /* It's always 2 */
    _retu->_padding = 3;             /* If some additional data is needed about the packet */
    _retu->_extension = 0;           /* If extension to header is needed */
    _retu->_cc        = 1;           /* It basically represents amount of contributors */
    _retu->_csrc      = NULL;        /* Container */
    _retu->_ssrc      = get_random_number ( -1 );
    _retu->_marker    = 1;
    _retu->_payload_type = 127;      /* You should specify payload type */
    _retu->_sequence_number = get_random_number ( _MAX_SEQU_NUM );
    _retu->_last_sequence_number = 0;/* Do not touch this variable */
    /* Sequence starts at random number and goes to _MAX_SEQU_NUM */
    _retu->_initial_time = 0;        /* In seconds */
    _retu->_time_elapsed = 0;        /* In seconds */

    _retu->_ext_header = NULL;       /* When needed allocate */

    ALLOCATOR_S ( _retu->_csrc, uint32_t )
    _retu->_csrc[0] = _retu->_ssrc;  /* Set my ssrc to the list */
    /*
     *
     */
    memset ( LAST_SOCKET_DATA, '\0', MAX_UDP_PACKET_SIZE );
    return _retu;
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
            }
    else {
            _retu->_csrc = NULL;
            }

    _retu->_length = 8 + _CRSC_LEN ( _session->_cc );

    return _retu;
    }
















