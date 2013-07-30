/* helper.c
*
* Has some standard functions. !Red!
*
*
* Copyright (C) 2013 Tox project All Rights Reserved.
*
* This file is part of Tox.
*
* Tox is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* Tox is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with Tox. If not, see <http://www.gnu.org/licenses/>.
*
*/


#include "helper.h"
#include "network.h"

#include <arpa/inet.h> /* Fixes implicit function warning. Someone put this in core/network.h? !Red! */

static int _seed = -1; /* Not initiated */

int set_ip_port ( const char* _ip, short _port, void* _dest )
    {
    if ( !_dest ) {
            return FAILURE;
            }

    IP_Port* _dest_c = ( IP_Port* ) _dest;

    _dest_c->ip.i = inet_addr ( _ip );
    _dest_c->port = htons ( _port );

    return SUCCESS;
    }

uint32_t get_random_number ( uint32_t _max )
    {
    if ( _seed < 0 ) {
            srand ( unix_time() );
            _seed++;
            }

    if ( _max <= 0 ) {
            return rand();
            }
    else {
            return rand() % _max;
            }
    }

void memadd ( uint8_t* _dest, uint16_t _from, const uint8_t* _source, uint16_t _size )
    {
    uint16_t it;

    for ( it = 0; _from < _size; _from ++ ) {
            _dest[_from] = _source[it];
            it ++;
            }
    }

void memcpy_from ( uint8_t* _dest, uint16_t _from, const uint8_t* _source, uint16_t _size )
    {
    for ( uint16_t _it = 0; _from < _size; _it++ ) {
            _dest[_it] = _source[_from];
            _from ++;
            }
    }