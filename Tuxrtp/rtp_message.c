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

uint32_t payload_table[] = /* PAYLOAD TABLE */
{
	8000, 8000, 8000, 8000, 8000, 8000, 16000, 8000, 8000, 8000,	/* 0-9 */
	44100, 44100, 0, 0, 90000, 8000, 11025, 22050, 0, 0,		    /* 10-19 */
	0, 0, 0, 0, 0, 90000, 90000, 0, 90000, 0,			            /* 20-29 */
	0, 90000, 90000, 90000, 90000, 0, 0, 0, 0, 0,			        /* 30-39 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 40-49 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 50-59 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 60-69 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 70-79 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 80-89 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 90-99 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 100-109 */
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,					                /* 110-119 */
	0, 0, 0, 0, 0, 0, 0, 0						                    /* 120-127 */
};

rtp_header_t* rtp_extract_header ( uint8_t* _payload, size_t _size )
{
    if ( _size < _MIN_LENGHT_ ) {
        return NULL;
    }

    rtp_header_t* _retu = ( rtp_header_t* ) malloc ( sizeof ( rtp_header_t ) );

    _retu->_flags = _payload[0];
    _retu->_marker_payload_t = _payload[1];

    _retu->_sequence_number = ( ( uint16_t ) _payload[2] << 8 ) | _payload[3];

    _retu->_ssrc = ( ( uint32_t ) _payload[4] << 24 ) |
                   ( ( uint32_t ) _payload[5] << 16 ) |
                   ( ( uint32_t ) _payload[6] << 8 )  |
                   ( ( uint32_t ) _payload[7] ) ;

    size_t i = 8; /* This is always like 8 bytes long */

    uint8_t cc = rtp_header_get_flag_CSRC_count ( _retu );

    _retu->_length = i + ( cc * 4 );

    if ( cc > 0 ) {
        _retu->_csrc = ( uint32_t* ) malloc ( sizeof ( uint32_t ) * cc );
    } else { /* But this should not happen ever */
        _retu->_csrc = NULL;
        return _retu;
    }


    for ( size_t x = 0; x < cc; x++ ) {
        _retu->_csrc[x] = ( ( uint32_t ) _payload[i]     << 24 ) |
                          ( ( uint32_t ) _payload[i + 1] << 16 ) |
                          ( ( uint32_t ) _payload[i + 2] << 8 )  |
                          ( ( uint32_t ) _payload[i + 3] ) ;
        i += 4;
    }


    return _retu;
}

uint8_t* rtp_add_header ( rtp_header_t* _header, uint8_t* _payload, size_t _size )
{
    if ( _size < _MIN_LENGHT_ ) {
        return FAILURE;
    }

    uint8_t cc = rtp_header_get_flag_CSRC_count ( _header );

    _payload[0] = _header->_flags;
    _payload[1] = _header->_marker_payload_t;

    _payload[2] = ( _header->_sequence_number >> 8 );
    _payload[3] = ( _header->_sequence_number );

    _payload[4] = ( _header->_ssrc >> 24 );
    _payload[5] = ( _header->_ssrc >> 16 );
    _payload[6] = ( _header->_ssrc >> 8 );
    _payload[7] = ( _header->_ssrc );

    size_t i = 8;

    for ( size_t x = 0; x < cc; x++ ) {
        _payload[i]  = ( _header->_csrc[x] >> 24 ); i++;
        _payload[i]  = ( _header->_csrc[x] >> 16 ); i++;
        _payload[i]  = ( _header->_csrc[x] >> 8 ); i++;
        _payload[i]  = ( _header->_csrc[x] ); i++;
    }



    return SUCCESS;
}

uint16_t rtp_header_get_size ( rtp_header_t* _header )
{
    return ( 8 + ( rtp_header_get_flag_CSRC_count ( _header ) * 4 ) );
}
uint32_t rtp_get_payload_type_value ( rtp_header_t* _header )
{
    return payload_table[rtp_header_get_setting_payload_type(_header)];
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
    } else {
        _retu = _header->_marker_payload_t;
    }

    /* return to start value */
    return _retu;
}

/*  */


