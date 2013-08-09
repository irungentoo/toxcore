/* rtp_helper.h
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

#ifndef _RTP__HELPER_H_
#define _RTP__HELPER_H_

#include <time.h>
#include <inttypes.h>

/* Current time, unix format */
#define unix_time() ((uint32_t)time(NULL))

#define SUCCESS 0
#define FAILURE -1


/* Core adaptation helper */

int set_ip_port ( const char* _ip, short _port, void* _cont );
uint32_t get_random_number ( uint32_t _max );

void memadd ( uint8_t* _dest, size_t _from, const uint8_t* _source, size_t _size );
void memcpy_from ( uint8_t* _dest, size_t _from, const uint8_t* _source, size_t _size );

#endif /* _RTP__HELPER_H_ */
