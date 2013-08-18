/*   Allocator.h
 *
 *   It contains some allocation macros.  !Red!
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

#ifndef _RTP__ALLOCATOR_H_
#define _RTP__ALLOCATOR_H_

#include <malloc.h>
#include "rtp_allocator.h"

#define ALLOCATOR_VAR(VAR, TYPE, NUM) TYPE* VAR = malloc(sizeof(TYPE) * NUM);
#define ALLOCATOR(VAR, TYPE, NUM) VAR = malloc(sizeof(TYPE) * NUM);

#define ALLOCATOR_S(VAR, TYPE) ALLOCATOR(VAR,TYPE,1)
#define ALLOCATOR_V(VAR, TYPE) ALLOCATOR_VAR(VAR, TYPE, 1)

#define ALLOCATOR_LIST_S(VAR, TYPE, VAL) ALLOCATOR(VAR,TYPE,1) VAR->next=VAL;
#define ALLOCATOR_LIST_D(VAR, TYPE, VAL) ALLOCATOR_LIST_S(VAR, TYPE, NULL) VAR->prev=VAL;

#define ALLOCATOR_LIST_NEXT_S(VAR, TYPE)      { TYPE* p; ALLOCATOR_LIST_S(p, TYPE, NULL) VAR->next = p; VAR = p;}
#define ALLOCATOR_LIST_NEXT_D(VAR, TYPE)      { TYPE* p; ALLOCATOR_LIST_D(p, TYPE, VAR) VAR->next = p; VAR = p; }

#define DEALLOCATOR(VAR) free(VAR);

#define DEALLOCATOR_LIST_S(VAR, TYPE) { TYPE* _next; _next = VAR->next; do { free(VAR); VAR = _next; if ( _next ) _next = VAR->next; } while ( _next ); }


#define DYNAMIC_STRING(VAR, SIZE) { ALLOCATOR(VAR, char, SIZE) memset(VAR, '\0', SIZE); }


#define SET_ALLOCATE(VAR, NUM)  VAR = realloc(VAR, sizeof *VAR * NUM );
#define ADD_ALLOCATE(VAR, PREV) SET_ALLOCATE(VAR, PREV + 1)
#define REM_ALLOCATE(VAR, PREV) SET_ALLOCATE(VAR, PREV - 1)

#endif /* _RTP__ALLOCATOR_H_ */
