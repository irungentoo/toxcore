/* rtp_helper.c
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


#include "rtp_helper.h"
#include "../core/network.h"

#include <arpa/inet.h> /* Fixes implicit function warning. */

static int _seed = -1; /* Not initiated */

int set_ip_port ( const char* _ip, unsigned short _port, void* _dest )
{
    if ( !_dest ) {
        return FAILURE;
    }

    IP_Port* _dest_c = ( IP_Port* ) _dest;

    _dest_c->ip.i = resolve_addr ( _ip );
    _dest_c->port = htons ( _port );

    return SUCCESS;
}

uint32_t get_random_number ( uint32_t _max )
{
    if ( _seed < 0 ) {
        srand ( _time );
        _seed++;
    }

    if ( _max <= 0 ) {
        return (unsigned) rand();
    } else {
        return (unsigned) rand() % _max;
    }
}

void t_memcpy ( data_t* _dest, const data_t* _source, size_t _size )
{
    /*
     * Using countdown to zero method
     * It's quite much faster than for(_it = 0; _it < _size; _it++);
     */
    size_t _it = _size;

    do{
        _it--;
        _dest[_it] = _source[_it];
    } while ( _it );
}

data_t* t_memset ( data_t* _dest, int _valu, size_t _size )
{
    /*
     * Again using countdown to zero method
     */
    size_t _it = _size;

    do{
        _it--;
        _dest[_it] = _valu;
    } while ( _it );

    return _dest;
}
