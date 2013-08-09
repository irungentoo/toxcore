/*   rtp_impl.c
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

#include "rtp_allocator.h"
#include "rtp_message.h"

#define RTP_VERSION 2

uint8_t LAST_SOCKET_DATA[MAX_UDP_PACKET_SIZE];

/* Extension header types */
#define RTP_EXT_TYPE_RESOLUTION 1

/* More?
 *
const uint8_t RTP_EXT_MARK_SOMETHING = 2;
 */

/* Some defines */

#define RTP_PACKET_ID 100

/* Payload identifiers */

/* Audio */
#define _PAYLOAD_OPUS 96

/* Video */
#define _PAYLOAD_VP8 106

/* End of Payload identifiers */

/* End of defines */

typedef struct rtp_dest_list_s {
    IP_Port                 _dest;
    struct rtp_dest_list_s* next;
    /* int con_id; */

} rtp_dest_list_t;

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
    uint64_t                _initial_time;
    uint32_t                _time_elapsed;
    uint32_t                _ssrc;
    uint32_t*               _csrc;


    /* If some additional data must be sent via message
     * apply it here. Only by allocating this member you will be
     * automatically placing it within a message.
     */

    rtp_ext_header_t*       _ext_header;

    int                     _max_users;    /* -1 undefined */

    uint64_t                _packets_sent; /* measure packets */
    uint64_t                _packets_recv;

    uint64_t                _bytes_sent;
    uint64_t                _bytes_recv;

    uint64_t                _packet_loss;

    const char*             _last_error;

    struct rtp_dest_list_s* _dest_list;
    struct rtp_dest_list_s* _last_user; /* a tail for faster appending */

} rtp_session_t;


/*
 * Now i don't believe we need to store this _from thing every time
 * since we have csrc table but will leave it like this for a while
 */

/* Functions handling receiving */
rtp_msg_t*      rtp_recv_msg ( rtp_session_t* _session );
rtp_msg_t*      rtp_msg_parse ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from );

/* Functions handling sending */
int             rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* msg );
rtp_msg_t*      rtp_msg_new ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from );


/* Convenient functions for creating a header */
rtp_header_t*   rtp_build_header ( rtp_session_t* _session );

/* Functions handling session control */

/* Handling an rtp packet */
int             rtp_handlepacket(uint8_t * packet, uint32_t length, IP_Port source);

    /* Session initiation and termination. */
rtp_session_t*  rtp_init_session ( IP_Port _dest, int _max_users );
int             rtp_terminate_session( rtp_session_t* _session );

    /* Adding receiver */
int             rtp_add_user ( rtp_session_t* _session, IP_Port _dest );

    /* Convenient functions for marking the resolution */
int             rtp_add_resolution_marking ( rtp_session_t* _session, uint16_t _width, uint16_t _height );
int             rtp_remove_resolution_marking ( rtp_session_t* _session );
uint16_t        rtp_get_resolution_marking_height(rtp_ext_header_t* _header);
uint16_t        rtp_get_resolution_marking_width(rtp_ext_header_t* _header);

    /* Convenient functions for marking the payload */
void            rtp_set_payload_type ( rtp_session_t* _session, uint8_t _payload_value );
uint32_t        rtp_get_payload_type ( rtp_session_t* _session );

    /* Informational */
uint32_t        rtp_get_time_elapsed ( rtp_session_t* _session );

#endif /* _RTP__IMPL_H_ */
