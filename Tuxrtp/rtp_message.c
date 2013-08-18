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
#include "rtp_allocator.h"
#include "rtp_impl.h"

#include <assert.h>

/* Some defines */
#define _MIN_HEADER_LENGHT 11

/* End of defines */

rtp_header_t* rtp_extract_header ( uint8_t* _payload, size_t _from, size_t _size )
{
    if ( _size < _MIN_HEADER_LENGHT || !_payload ) {
        return NULL;
    }

    uint8_t* _it = &(_payload[_from]);

    ALLOCATOR_VAR(_retu, rtp_header_t, 1)

    _retu->_flags = *_it; ++_it;

    /* Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t cc = rtp_header_get_flag_CSRC_count ( _retu );

    _retu->_length = 8 + ( cc * 4 );

    if ( _retu->_length > _size ){
        DEALLOCATOR(_retu)
        return NULL;
    }

    _retu->_marker_payload_t = *_it; ++_it;

    _retu->_sequence_number = ( ( uint16_t ) *_it << 8 ) | *(_it + 1);

    _it += 2;

    _retu->_ssrc = ( ( uint32_t ) *_it       << 24 ) |
                   ( ( uint32_t ) *(_it + 1) << 16 ) |
                   ( ( uint32_t ) *(_it + 2) << 8 )  |
                   ( ( uint32_t ) *(_it + 3) ) ;

    if ( cc > 0 ) {
        _retu->_csrc = ( uint32_t* ) malloc ( sizeof ( uint32_t ) * cc );
    } else { /* But this should not happen ever */
        _retu->_csrc = NULL;
        return _retu;
    }

    size_t x;
    for ( x = 0; x < cc; x++ ) {
        _it += 4;
        _retu->_csrc[x] = ( ( uint32_t ) *_it        << 24 ) |
                          ( ( uint32_t ) *(_it + 1)  << 16 ) |
                          ( ( uint32_t ) *(_it + 2)  << 8 )  |
                          ( ( uint32_t ) *(_it + 3) ) ;
    }

    return _retu;
}

rtp_ext_header_t* rtp_extract_ext_header ( uint8_t* _payload, size_t _from )
{
    uint8_t* _it = &(_payload[_from]);

    ALLOCATOR_VAR(_retu, rtp_ext_header_t, 1)

    _retu->_ext_len  = ( ( uint16_t ) *_it << 8 ) | *(_it + 1); _it+=2;
    _retu->_ext_type = ( ( uint16_t ) *_it << 8 ) | *(_it + 1); _it-=2;

    ALLOCATOR(_retu->_hd_ext, uint32_t, _retu->_ext_len)

    size_t i;
    for ( i = 0; i < _retu->_ext_len; i++ ){
        _it += 4;
        _retu->_hd_ext[i] = ( (uint32_t) *_it       << 24 ) |
                            ( (uint32_t) *(_it + 1) << 16 ) |
                            ( (uint32_t) *(_it + 2) << 8 )  |
                            ( (uint32_t) *(_it + 3) ) ;
    }

    return _retu;
}

uint8_t* rtp_add_header ( rtp_header_t* _header, uint8_t* _payload)
{
    uint8_t cc = rtp_header_get_flag_CSRC_count ( _header );

    uint8_t* _it = _payload;

    *_it = _header->_flags; ++_it;
    *_it = _header->_marker_payload_t; ++_it;

    *_it = ( _header->_sequence_number >> 8 ); ++_it;
    *_it = ( _header->_sequence_number ); ++_it;

    *_it = ( _header->_ssrc >> 24 ); ++_it;
    *_it = ( _header->_ssrc >> 16 ); ++_it;
    *_it = ( _header->_ssrc >> 8 ); ++_it;
    *_it = ( _header->_ssrc );

    size_t x;
    for ( x = 0; x < cc; x++ ) {
        ++_it;
        *_it = ( _header->_csrc[x] >> 24 );  ++_it;
        *_it = ( _header->_csrc[x] >> 16 );  ++_it;
        *_it = ( _header->_csrc[x] >> 8 );   ++_it;
        *_it = ( _header->_csrc[x] );
    }

    return _it;
}

uint8_t* rtp_add_extention_header(rtp_ext_header_t* _header, uint8_t* _payload)
{
    uint8_t* _it = _payload;

    *_it = ( _header->_ext_len >> 8 ); _it++;
    *_it = ( _header->_ext_len ); _it++;

    *_it = ( _header->_ext_type >> 8 ); ++_it;
    *_it = ( _header->_ext_type );

    size_t x;

    for ( x = 0; x < _header->_ext_len; x++ ) {

        ++_it;

        *_it = ( _header->_hd_ext[x] >> 24 );  ++_it;
        *_it = ( _header->_hd_ext[x] >> 16 );  ++_it;
        *_it = ( _header->_hd_ext[x] >> 8 );  ++_it;
        *_it = ( _header->_hd_ext[x] );
    }

    return _it;
}

size_t rtp_header_get_size ( rtp_header_t* _header )
{
    return ( 8 + ( rtp_header_get_flag_CSRC_count ( _header ) * 4 ) );
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

    ( _header->_marker_payload_t ) &= 0x7F;
    ( _header->_marker_payload_t ) |= ( ( ( value ) << 7 ) /*& 0x80 */ );
}

void rtp_header_add_setting_payload ( rtp_header_t* _header, int value )
{
    if ( value > 127 )
        value = 127; /* Well set to maximum */

    ( _header->_marker_payload_t ) &= 0x80;
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
    } else {
        _retu = _header->_marker_payload_t;
    }

    /* return to start value */
    return _retu;
}

/*  */


