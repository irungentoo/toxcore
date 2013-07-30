/*   rtp_message.c
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

#include "rtp_message.h"
#include <assert.h>
#define _MIN_LENGHT_ 11

rtp_header_t* rtp_extract_header ( uint8_t* payload, size_t size )
    {
    if ( size < _MIN_LENGHT_ ) {
            return NULL;
            }

    rtp_header_t* _retu = ( rtp_header_t* ) malloc ( sizeof ( rtp_header_t ) );

    _retu->_flags = payload[0];
    _retu->_marker_payload_t = payload[1];

    _retu->_sequence_number = ( ( uint16_t ) payload[2] << 8 ) | payload[3];

    _retu->_ssrc = ( ( uint32_t ) payload[4] << 24 ) |
                   ( ( uint32_t ) payload[5] << 16 ) |
                   ( ( uint32_t ) payload[6] << 8 )  |
                   ( ( uint32_t ) payload[7] ) ;

    uint8_t cc = rtp_header_get_flag_CSRC_count ( _retu );

    if ( cc > 0 ) {
            _retu->_csrc = ( uint32_t* ) malloc ( sizeof ( uint32_t ) * cc );
            }
    else { /* But this should not happen ever */
            _retu->_csrc = NULL;
            return _retu;
            }

    size_t i = 8;

    for ( size_t x = 0; x < cc; x++ ) {
            _retu->_csrc[x] = ( ( uint32_t ) payload[i]     << 24 ) |
                              ( ( uint32_t ) payload[i + 1] << 16 ) |
                              ( ( uint32_t ) payload[i + 2] << 8 )  |
                              ( ( uint32_t ) payload[i + 3] ) ;
            i += 4;
            }

    return _retu;
    }

uint8_t* rtp_add_header ( rtp_header_t* _header, uint8_t* payload, size_t size )
    {
    if ( size < _MIN_LENGHT_ ) {
            return FAILURE;
            }

    uint8_t cc = rtp_header_get_flag_CSRC_count ( _header );

    payload[0] = _header->_flags;
    payload[1] = _header->_marker_payload_t;

    payload[2] = ( _header->_sequence_number >> 8 );
    payload[3] = ( _header->_sequence_number );

    payload[4] = ( _header->_ssrc >> 24 );
    payload[5] = ( _header->_ssrc >> 16 );
    payload[6] = ( _header->_ssrc >> 8 );
    payload[7] = ( _header->_ssrc );

    size_t i = 8;

    for ( size_t x = 0; x < cc; x++ ) {
            payload[i]  = ( _header->_csrc[x] >> 24 ); i++;
            payload[i]  = ( _header->_csrc[x] >> 16 ); i++;
            payload[i]  = ( _header->_csrc[x] >> 8 ); i++;
            payload[i]  = ( _header->_csrc[x] ); i++;
            }



    return SUCCESS;
    }

uint16_t rtp_header_get_size(rtp_header_t* _header)
{
    return ( 8 + ( rtp_header_get_flag_CSRC_count(_header) * 4 ) );
}

/* Setting flags */

void rtp_header_add_flag_version ( rtp_header_t* _header, int value )
    {
    ( _header->_flags ) &= 0x3F;
    ( _header->_flags ) |= ( ( ( value ) << 6 ) & 0xC0 );
    }

void rtp_header_add_flag_padding ( rtp_header_t* _header, int value )
    {
    if ( value > 0 ) {
            value = 1; /* It can only be 1 */
            }

    ( _header->_flags ) &= 0xDF;
    ( _header->_flags ) |= ( ( ( value ) << 5 ) & 0x20 );
    }

void rtp_header_add_flag_extension ( rtp_header_t* _header, int value )
    {
    if ( value > 0 ) {
            value = 1; /* It can only be 1 */
            }

    ( _header->_flags ) &= 0xEF;
    ( _header->_flags ) |= ( ( ( value ) << 4 ) & 0x10 );
    }

void rtp_header_add_flag_CSRC_count ( rtp_header_t* _header, int value )
    {
    ( _header->_flags ) &= 0xF0;
    ( _header->_flags ) |= ( ( value ) & 0x0F );
    }

void rtp_header_add_setting_marker ( rtp_header_t* _header, int value )
    {
    if ( value > 1 )
        value = 1;

    /*( _header->_marker_payload_t ) &= 0x7F;*/
    ( _header->_marker_payload_t ) |= ( ( ( value ) << 7 ) /*& 0x80 */ );
    }

void rtp_header_add_setting_payload ( rtp_header_t* _header, int value )
    {
    if ( value > 127 )
        value = 127; /* Well set to maximum */

    /*( _header->_marker_payload_t ) &= 0x80;*/
    ( _header->_marker_payload_t ) |= ( ( value ) /* & 0x7F */ );
    }

/* Getting values from flags */
uint8_t rtp_header_get_flag_version ( rtp_header_t* _header )
    {
    return ( _header->_flags & 0xd0 ) >> 6;
    }

uint8_t rtp_header_get_flag_padding ( rtp_header_t* _header )
    {
    return ( _header->_flags & 0x20 ) >> 5;
    }

uint8_t rtp_header_get_flag_extension ( rtp_header_t* _header )
    {
    return ( _header->_flags & 0x10 ) >> 4;
    }

uint8_t rtp_header_get_flag_CSRC_count ( rtp_header_t* _header )
    {
    return ( _header->_flags & 0x0f );
    }


/* TODO: MAKE THIS A BIT FASTER */
uint8_t rtp_header_get_setting_marker ( rtp_header_t* _header )
    {
    uint8_t _retu = ( ( _header->_marker_payload_t ) >> 7 );

    if ( _header->_marker_payload_t >> 7 == 1 ) {
            _header->_marker_payload_t ^ 0x80;
            }

    return _retu;
    }

uint8_t rtp_header_get_setting_payload_type ( rtp_header_t* _header )
    {
    uint8_t _retu;

    if ( _header->_marker_payload_t >> 7 == 1 ) {
            _header->_marker_payload_t ^= 0x80;
            _retu = _header->_marker_payload_t;
            _header->_marker_payload_t ^= 0x80;
            }
    else {
            _retu = _header->_marker_payload_t;
            }

    /* return to start value */
    return _retu;
    }

/*  */


