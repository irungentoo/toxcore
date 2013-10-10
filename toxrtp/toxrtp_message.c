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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxrtp_message.h"
#include "toxrtp_allocator.h"
#include "toxrtp.h"
#include <stdio.h>

#ifdef _USE_ERRORS
#include "toxrtp_error_id.h"
#endif /* _USE_ERRORS */

#include <assert.h>

/* Some defines */

/* End of defines */

void rtp_header_print (const rtp_header_t* _header)
{
    printf("Header:      \n"
           "Version:    %d\n"
           "Padding:    %d\n"
           "Ext:        %d\n"
           "CC:         %d\n"
           "marker:     %d\n"
           "payload typ:%d\n\n"
           "sequ num:   %d\n"
           "Timestamp:  %d\n"
           "SSrc:       %d\n"
           "CSrc:       %d\n"
           "Lenght:     %d\n"
           ,rtp_header_get_flag_version(_header)
           ,rtp_header_get_flag_padding(_header)
           ,rtp_header_get_flag_extension(_header)
           ,rtp_header_get_flag_CSRC_count(_header)
           ,rtp_header_get_setting_marker(_header)
           ,rtp_header_get_setting_payload_type(_header)
           ,_header->_sequence_number
           ,_header->_timestamp
           ,_header->_ssrc
           ,_header->_csrc[0]
           ,_header->_length
           );
}

rtp_header_t* rtp_extract_header ( const uint8_t* _payload, size_t _bytes )
{
    if ( !_payload ) {
        t_perror ( RTP_ERROR_PAYLOAD_NULL );
        return NULL;
    }
    const uint8_t* _it = _payload;
    ALLOCATOR_VAR ( _retu, rtp_header_t, 1 )
    _retu->_flags = *_it; ++_it;
    
    /* This indicates if the first 2 bytes are valid.
     * Now it my happen that this is out of order but
     * it cuts down chances of parsing some invalid value
     */
    if ( rtp_header_get_flag_version(_retu) != RTP_VERSION ){
        printf("Invalid version: %d\n", rtp_header_get_flag_version(_retu));
        //assert(rtp_header_get_flag_version(_retu) == RTP_VERSION);
        /* Deallocate */
        //DEALLOCATOR(_retu);
        //return NULL;
    }

    /*
     * Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t cc = rtp_header_get_flag_CSRC_count ( _retu );
    uint32_t _lenght = _MIN_HEADER_LENGTH + ( cc * 4 );

    if ( _bytes < _lenght ) {
        t_perror ( RTP_ERROR_PAYLOAD_INVALID );
        return NULL;
    }

    if ( cc > 0 ) {
        _retu->_csrc = calloc ( sizeof ( uint32_t ) * cc,1 );
    } else { /* But this should not happen ever */
        t_perror ( RTP_ERROR_HEADER_PARSING );
        return NULL;
    }


    _retu->_marker_payload_t = *_it; ++_it;
    _retu->_length = _lenght;
    _retu->_sequence_number = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 );

    _it += 2;

    _retu->_timestamp = ( ( uint32_t ) * _it         << 24 ) |
                        ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                        ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                        (              * ( _it + 3 ) ) ;

    _it += 4;

    _retu->_ssrc = ( ( uint32_t ) * _it         << 24 ) |
                   ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                   ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                   ( ( uint32_t ) * ( _it + 3 ) ) ;


    size_t x;
    for ( x = 0; x < cc; x++ ) {
        _it += 4;
        _retu->_csrc[x] = ( ( uint32_t ) * _it          << 24 ) |
                          ( ( uint32_t ) * ( _it + 1 )  << 16 ) |
                          ( ( uint32_t ) * ( _it + 2 )  << 8 )  |
                          ( ( uint32_t ) * ( _it + 3 ) ) ;
    }

    return _retu;
}

rtp_ext_header_t* rtp_extract_ext_header ( const uint8_t* _payload, size_t _bytes )
{
    if ( !_payload ) {
        t_perror ( RTP_ERROR_PAYLOAD_NULL );
        return NULL;
    }



    const uint8_t* _it = _payload;

    ALLOCATOR_VAR ( _retu, rtp_ext_header_t, 1 )

    uint16_t _ext_len = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 ); _it += 2;

    if ( _bytes < ( _ext_len * sizeof(uint32_t) ) ) {
        t_perror ( RTP_ERROR_PAYLOAD_INVALID );
        return NULL;
    }

    _retu->_ext_len  = _ext_len;
    _retu->_ext_type = ( ( uint16_t ) * _it << 8 ) | * ( _it + 1 ); _it -= 2;

    ALLOCATOR ( _retu->_hd_ext, uint32_t, _ext_len )

    uint32_t* _hd_ext = _retu->_hd_ext;
    size_t i;
    for ( i = 0; i < _ext_len; i++ ) {
        _it += 4;
        _hd_ext[i] = ( ( uint32_t ) * _it         << 24 ) |
                     ( ( uint32_t ) * ( _it + 1 ) << 16 ) |
                     ( ( uint32_t ) * ( _it + 2 ) << 8 )  |
                     ( ( uint32_t ) * ( _it + 3 ) ) ;
    }

    return _retu;
}

uint8_t* rtp_add_header ( rtp_header_t* _header, uint8_t* _payload )
{
    uint8_t cc = rtp_header_get_flag_CSRC_count ( _header );

    uint8_t* _it = _payload;

    *_it = _header->_flags; ++_it;
    *_it = _header->_marker_payload_t; ++_it;

    *_it = ( _header->_sequence_number >> 8 ); ++_it;
    *_it = ( _header->_sequence_number ); ++_it;

    uint32_t _timestamp = _header->_timestamp;
    *_it = ( _timestamp >> 24 ); ++_it;
    *_it = ( _timestamp >> 16 ); ++_it;
    *_it = ( _timestamp >> 8 ); ++_it;
    *_it = ( _timestamp ); ++_it;

    uint32_t _ssrc = _header->_ssrc;
    *_it = ( _ssrc >> 24 ); ++_it;
    *_it = ( _ssrc >> 16 ); ++_it;
    *_it = ( _ssrc >> 8 ); ++_it;
    *_it = ( _ssrc );

    uint32_t *_csrc = _header->_csrc;
    size_t x;
    for ( x = 0; x < cc; x++ ) {
        ++_it;
        *_it = ( _csrc[x] >> 24 );  ++_it;
        *_it = ( _csrc[x] >> 16 );  ++_it;
        *_it = ( _csrc[x] >> 8 );   ++_it;
        *_it = ( _csrc[x] );
    }

    return _it;
}

uint8_t* rtp_add_extention_header ( rtp_ext_header_t* _header, uint8_t* _payload )
{
    uint8_t* _it = _payload;

    *_it = ( _header->_ext_len >> 8 ); _it++;
    *_it = ( _header->_ext_len ); _it++;

    *_it = ( _header->_ext_type >> 8 ); ++_it;
    *_it = ( _header->_ext_type );

    size_t x;

    uint32_t* _hd_ext = _header->_hd_ext;
    for ( x = 0; x < _header->_ext_len; x++ ) {
        ++_it;
        *_it = ( _hd_ext[x] >> 24 );  ++_it;
        *_it = ( _hd_ext[x] >> 16 );  ++_it;
        *_it = ( _hd_ext[x] >> 8 );  ++_it;
        *_it = ( _hd_ext[x] );
    }

    return _it;
}

size_t rtp_header_get_size ( const rtp_header_t* _header )
{
    return ( 8 + ( rtp_header_get_flag_CSRC_count ( _header ) * 4 ) );
}
/* Setting flags */

void rtp_header_add_flag_version ( rtp_header_t* _header, uint32_t value )
{
    ( _header->_flags ) &= 0x3F;
    ( _header->_flags ) |= ( ( ( value ) << 6 ) & 0xC0 );
}

void rtp_header_add_flag_padding ( rtp_header_t* _header, uint32_t value )
{
    if ( value > 0 ) {
        value = 1; /* It can only be 1 */
    }

    ( _header->_flags ) &= 0xDF;
    ( _header->_flags ) |= ( ( ( value ) << 5 ) & 0x20 );
}

void rtp_header_add_flag_extension ( rtp_header_t* _header, uint32_t value )
{
    if ( value > 0 ) {
        value = 1; /* It can only be 1 */
    }

    ( _header->_flags ) &= 0xEF;
    ( _header->_flags ) |= ( ( ( value ) << 4 ) & 0x10 );
}

void rtp_header_add_flag_CSRC_count ( rtp_header_t* _header, uint32_t value )
{
    ( _header->_flags ) &= 0xF0;
    ( _header->_flags ) |= ( ( value ) & 0x0F );
}

void rtp_header_add_setting_marker ( rtp_header_t* _header, uint32_t value )
{
    if ( value > 1 )
        value = 1;

    ( _header->_marker_payload_t ) &= 0x7F;
    ( _header->_marker_payload_t ) |= ( ( ( value ) << 7 ) /*& 0x80 */ );
}

void rtp_header_add_setting_payload ( rtp_header_t* _header, uint32_t value )
{
    if ( value > 127 )
        value = 127; /* Well set to maximum */

    ( _header->_marker_payload_t ) &= 0x80;
    ( _header->_marker_payload_t ) |= ( ( value ) /* & 0x7F */ );
}

/* Getting values from flags */
uint8_t rtp_header_get_flag_version ( const rtp_header_t* _header )
{
    return ( _header->_flags & 0xd0 ) >> 6;
}

uint8_t rtp_header_get_flag_padding ( const rtp_header_t* _header )
{
    return ( _header->_flags & 0x20 ) >> 5;
}

uint8_t rtp_header_get_flag_extension ( const rtp_header_t* _header )
{
    return ( _header->_flags & 0x10 ) >> 4;
}

uint8_t rtp_header_get_flag_CSRC_count ( const rtp_header_t* _header )
{
    return ( _header->_flags & 0x0f );
}
uint8_t rtp_header_get_setting_marker ( const rtp_header_t* _header )
{
    return ( _header->_marker_payload_t ) >> 7;
}
uint8_t rtp_header_get_setting_payload_type ( const rtp_header_t* _header )
{
    /*
       uint8_t _retu;

       if ( _header->_marker_payload_t >> 7 == 1 ) {
           _header->_marker_payload_t ^= 0x80;
           _retu = _header->_marker_payload_t;
           _header->_marker_payload_t ^= 0x80;
       } else {
           _retu = _header->_marker_payload_t;
       }
    */
    /* return to start value
    return _retu; */
    return _header->_marker_payload_t & 0x7f;
}

/*  */


