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


#ifndef _RTP__IMPL_H_
#define _RTP__IMPL_H_

#define RTP_VERSION 2
#include <inttypes.h>
#include "tox.h"

/* Extension header types */
#define RTP_EXT_TYPE_RESOLUTION 1

/* More?
 *
const uint8_t RTP_EXT_MARK_SOMETHING = 2;
 */

/* Some defines */

#define RTP_PACKET 70

/* Payload identifiers */

/* Audio */
#define _PAYLOAD_OPUS 96

/* Video */
#define _PAYLOAD_VP8 106

/* End of Payload identifiers */

/* End of defines */


/* Our main session descriptor.
 * It measures the session variables and controls
 * the entire session. There are functions for manipulating
 * the session so tend to use those instead of directly accessing
 * session parameters.
 */
typedef struct rtp_session_s {
    uint8_t                 _version;
    uint8_t                 _padding;
    uint8_t                 _extension;
    uint8_t                 _cc;
    uint8_t                 _marker;
    uint8_t                 _payload_type;
    uint16_t                _sequence_number;      /* Set when sending */
    uint16_t                _last_sequence_number; /* Check when recving msg */
    uint32_t                _initial_time;
    uint32_t                _time_elapsed;
    uint32_t                _current_timestamp;
    uint32_t                _ssrc;
    uint32_t*               _csrc;


    /* If some additional data must be sent via message
     * apply it here. Only by allocating this member you will be
     * automatically placing it within a message.
     */

    struct rtp_ext_header_s*    _ext_header;

    int                         _max_users;    /* -1 undefined */

    uint64_t                    _packets_sent; /* measure packets */
    uint64_t                    _packets_recv;

    uint64_t                    _bytes_sent;
    uint64_t                    _bytes_recv;

    uint64_t                    _packet_loss;

    const char*                 _last_error;

    struct rtp_dest_list_s*     _dest_list;
    struct rtp_dest_list_s*     _last_user; /* a tail for faster appending */

    struct rtp_msg_s*           _oldest_msg;
    struct rtp_msg_s*           _last_msg; /* tail */

    uint16_t                    _prefix_length;
    uint8_t*                    _prefix;

    /* Specifies multiple session use.
     * When using one session it uses default value ( -1 )
     * Otherwise it's set to 1 and rtp_register_msg () is required
     */
    int                         _multi_session;

} rtp_session_t;


/*
 * Now i don't believe we need to store this _from thing every time
 * since we have csrc table but will leave it like this for a while
 */


void                    rtp_free_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg );

/* Functions handling receiving */
struct rtp_msg_s*       rtp_recv_msg ( rtp_session_t* _session );
struct rtp_msg_s*       rtp_msg_parse ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length );
int                     rtp_register_msg ( rtp_session_t* _session, struct rtp_msg_s* );

/* Functions handling sending */
int                     rtp_send_msg ( rtp_session_t* _session, struct rtp_msg_s* _msg, int _socket );
struct rtp_msg_s*       rtp_msg_new ( rtp_session_t* _session, const uint8_t* _data, uint32_t _length );


/* Convenient functions for creating a header */
struct rtp_header_s*    rtp_build_header ( rtp_session_t* _session );

/* Functions handling session control */

/* Handling an rtp packet */
/* int             rtp_handlepacket(uint8_t * packet, uint32_t length, IP_Port source); */

/* Session initiation and termination.
 * Set _multi_session to -1 if not using multiple sessions
 */
rtp_session_t*          rtp_init_session ( int _max_users, int _multi_session );
int                     rtp_terminate_session ( rtp_session_t* _session );

/* Adding receiver */
int                     rtp_add_receiver ( rtp_session_t* _session, tox_IP_Port* _dest );

/* Convenient functions for marking the resolution */
int             rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height );
int             rtp_remove_resolution_marking ( rtp_session_t* _session );
uint16_t        rtp_get_resolution_marking_height ( struct rtp_ext_header_s* _header );
uint16_t        rtp_get_resolution_marking_width ( struct rtp_ext_header_s* _header );

/* Convenient functions for marking the payload */
void            rtp_set_payload_type ( rtp_session_t* _session, uint8_t _payload_value );
uint32_t        rtp_get_payload_type ( rtp_session_t* _session );

/* When using RTP in core be sure to set prefix when sending via rtp_send_msg */
int             rtp_set_prefix ( rtp_session_t* _session, uint8_t* _prefix, uint16_t _prefix_length );

#endif /* _RTP__IMPL_H_ */
