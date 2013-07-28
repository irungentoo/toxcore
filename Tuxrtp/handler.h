/*   handler.h
 *
 *   Rtp handler. It's and interface for Rtp. You will use this as the way to communicate to
 *   Rtp session and vice versa. !Red!
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

#ifndef _HANDLER_H_
#define _HANDLER_H_


#include "rtp_impl.h"
#include "../core/helper.h"


int             rtp_add_user ( rtp_session_t* _session, IP_Port _dest );
int             rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* msg );
rtp_msg_t*      rtp_recv_msg ( rtp_session_t* _session ); /* function made for threading */
rtp_msg_t*      rtp_msg_new ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from );  /* Making new */

/* Now i don't believe we need to store this _from thingy every time
 * since we have csrc table but will leave it like this for a while
 */
rtp_msg_t*      rtp_msg_parse ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from ); /* When recved msg */

#endif /* _HANDLER_H_ */
