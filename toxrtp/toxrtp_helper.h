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
/*#define _time ((uint32_t)time(NULL))*/

#define SUCCESS 0
#define FAILURE -1

#define _USE_ERRORS

#define RUN_IN_THREAD(_func, _thread_id, _arg_ptr) \
if ( pthread_create ( &_thread_id, NULL, _func, _arg_ptr ) ) { \
    pthread_detach ( _thread_id ); \
}

/* Core adaptation helper */
int t_setipport ( const char* _ip, unsigned short _port, void* _cont );
uint32_t t_random ( uint32_t _max );

/* It's a bit faster than the memcpy it self and more optimized for using
 * a uint8_t since memcpy has optimizations when copying "words" i.e. long type.
 * Otherwise it just copies char's while we need only uint8_t
 */
void t_memcpy ( uint8_t* _dest, const uint8_t* _source, size_t _size );


/* This is our memset. It's also a bit faster than the memset for it
 * does not cast _dest to char* and uses faster loop algorithm.
 */
uint8_t* t_memset ( uint8_t* _dest, uint8_t _valu, size_t _size );

/* Get null terminated len */
size_t t_memlen ( const uint8_t* _valu );

/* finds location of substring */
size_t t_strfind ( const uint8_t* _str, const uint8_t* _substr );

/* string alloc and copy ( ! must be null terminated ) */
uint8_t* t_strallcpy ( const uint8_t* _source );

/* Get current time in milliseconds */
uint64_t t_time();


#endif /* _RTP__HELPER_H_ */




