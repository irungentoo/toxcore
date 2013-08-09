/* substrate.h
 * The communications hub
 * See also: http://http://wiki.tox.im/index.php/Proposal:Slvr_Protocol_Rewrite
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

#include "network.h"

#ifdef __cplusplus
//extern "C" {
#endif

/* Type Definitions */

typedef uint8_t channel_t;

typedef struct {
	byte a[32];
} address_t;

typedef struct {
	
} connection_t;
   
typedef void(*channel_recv_callback_t)(connection_t*, byte*, size_t, uint64_t);

typedef void(*on_connection_callback_t)(connection_t*);

/* Globals */

extern address_t self_public_key;

/* Functions */
   
void substrate_init(byte* keydata);


#ifdef __cplusplus
//}
#endif

