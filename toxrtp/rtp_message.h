/*   rtp_message.h
 *
 *   Rtp Message handler. It handles message/header parsing.
 *   Refer to RTP: A Transport Protocol for Real-Time Applications ( RFC 3550 ) for more info. !Red!
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

#ifndef _RTP__MESSAGE_H_
#define _RTP__MESSAGE_H_

#include "../toxcore/network.h"
#include "rtp_helper.h"

/* Defines */

#define _MAX_SEQU_NUM 65535

/* End of defines */

typedef struct rtp_header_s {
    uint8_t      _flags;             /* Version(2),Padding(1), Ext(1), Cc(4) */
    uint8_t      _marker_payload_t;  /* Marker(1), PlayLoad Type(7) */
    uint16_t     _sequence_number;   /* Sequence Number */
    uint32_t     _timestamp;         /* Timestamp */
    uint32_t     _ssrc;              /* SSRC */
    uint32_t*    _csrc;              /* CSRC's table */

    uint32_t     _length;            /* A little something for allocation */

} rtp_header_t;

typedef struct rtp_ext_header_s {
    uint16_t     _ext_type;          /* Extension profile */
    uint16_t     _ext_len;           /* Number of extensions */
    uint32_t*    _hd_ext;            /* Extension's table */


} rtp_ext_header_t;

typedef struct rtp_msg_s {
    struct rtp_header_s*     _header;
    struct rtp_ext_header_s* _ext_header;
    uint32_t                 _header_lenght;

    data_t*                  _data;
    uint32_t                 _length;
    IP_Port                  _from;

    struct rtp_msg_s*        _next;
} rtp_msg_t;

/* Extracts the header from the payload starting at _from */
rtp_header_t*       rtp_extract_header ( const data_t* _payload, size_t _bytes );
rtp_ext_header_t*   rtp_extract_ext_header ( const data_t* _payload, size_t _bytes );


data_t*  rtp_add_header ( rtp_header_t* _header, const data_t* _payload );
data_t*  rtp_add_extention_header ( rtp_ext_header_t* _header, const data_t* _payload );

/* Gets the size of the header _header in bytes */
size_t  rtp_header_get_size ( const rtp_header_t* _header );

/* Adding flags and settings */
void    rtp_header_add_flag_version ( rtp_header_t* _header, uint32_t value );
void    rtp_header_add_flag_padding ( rtp_header_t* _header, uint32_t value );
void    rtp_header_add_flag_extension ( rtp_header_t* _header, uint32_t value );
void    rtp_header_add_flag_CSRC_count ( rtp_header_t* _header, uint32_t value );
void    rtp_header_add_setting_marker ( rtp_header_t* _header, uint32_t value );
void    rtp_header_add_setting_payload ( rtp_header_t* _header, uint32_t value );


/* Getting values from flags and settings */
uint8_t rtp_header_get_flag_version ( const rtp_header_t* _header );
uint8_t rtp_header_get_flag_padding ( const rtp_header_t* _header );
uint8_t rtp_header_get_flag_extension ( const rtp_header_t* _header );
uint8_t rtp_header_get_flag_CSRC_count ( const rtp_header_t* _header );
uint8_t rtp_header_get_setting_marker ( const rtp_header_t* _header );
uint8_t rtp_header_get_setting_payload_type ( const rtp_header_t* _header );

#endif /* _RTP__MESSAGE_H_ */
