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

#include "Allocator.h"
#include "rtp_message.h"

#define WINDOWS WIN32 || WIN64
#define _RTP_VERSION_ 2

typedef struct rtp_dest_list_s {
    IP_Port                 _dest;
    struct rtp_dest_list_s* next;
    /* int con_id; */

    } rtp_dest_list_t;



typedef struct rtp_session_s {
    uint8_t                 _version;
    uint8_t                 _padding;
    uint8_t                 _extension;
    uint8_t                 _cc;
    uint8_t                 _marker;
    uint8_t                 _payload_type;
    uint16_t                _sequence_number;      /* Set when sending */
    uint16_t                _last_sequence_number; /* Check when recving msg */
    uint16_t                _initial_time;
    uint32_t                _time_elapsed;
    uint32_t                _ssrc;
    uint32_t*               _csrc;

    rtp_ext_header_t*       _ext_header; /* If some additional data must be sent via message
                                          * apply it here. Only by allocating this member you will be
                                          * automatically placing it within a message.
                                          */

    int                     _max_users;    /* -1 undefined */

    unsigned int            _packets_sent; /* measure packets */
    unsigned int            _packets_recv;

    unsigned int            _bytes_sent;
    unsigned int            _bytes_recv;

    unsigned int            _packet_loss;

    const char*             _last_error;

    struct rtp_dest_list_s* _dest_list;
    struct rtp_dest_list_s* _last_user; /* a tail for faster appending */

    struct rtp_msg_s*       _messages;
    struct rtp_msg_s*       _last_msg;

    } rtp_session_t;


rtp_session_t*  rtp_init_session ( IP_Port _dest, int max_users ); /* you need to have at least 1 receiver */

uint8_t LAST_SOCKET_DATA[MAX_UDP_PACKET_SIZE];

#endif /* _RTP__IMPL_H_ */
