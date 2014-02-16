/* toxrtp_error.h
 *
 * Tox DHT bootstrap server daemon.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
 
#ifndef _RTP_ERROR_
#define _RTP_ERROR_

#define PRINT_FORMAT "Error %d: %s at %s:%d\n"
#define PRINT_ARGS( _errno ) _errno, t_rtperr(_errno), __FILE__, __LINE__


const char* t_rtperr ( int _errno );
void        t_rtperr_register ( int _id, const char* _info );

void        t_invoke_error ( int _id );
void        t_rtperr_print ( const char* _val, ... );


#ifdef _USE_ERRORS
#define t_perror( _errno ) t_rtperr_print ( PRINT_FORMAT, PRINT_ARGS ( _errno ) )
#else
#define t_perror( _errno )do { } while(0)
#endif /* _USE_ERRORS */

#ifdef _STDIO_H
#define t_errexit( _errno ) exit(-_errno)
#endif /* _STDIO_H */

#endif /* _RTP_ERROR_ */
