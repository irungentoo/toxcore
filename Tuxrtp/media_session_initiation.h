/* media_session_initiation.h
*
* Has function for session initiation along with session description.
* It follows the Tox API ( http://wiki.tox.im/index.php/Messaging_Protocol ). !Red!
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


#ifndef _RTP__SESSION__INITIATION_H_
#define _RTP__SESSION__INITIATION_H_

#include <inttypes.h>
#include "../core/Messenger.h"
#include "rtp_impl.h"
#include <pthread.h>

#define PACKET_ID_MEDIA 65

typedef enum {
    _none = 0,
    _inviting,
    _trying,
    _ringing,
    _starting,
    _started,
    _canceling,
    _rejecting,
    _ending,
    _end,

} state_t;

typedef struct media_session_s {
    rtp_session_t* _rtp_session;

    state_t _last_recv_state;

    pthread_t _thread_id;
    int _friend_id;
    /* Martijnvc add your media stuff here so this will be used in messenger */

} media_session_t;

/* OUR MAIN POOL FUNCTION */
/*
 * Forks it self to other thread and then handles the session initiation.
 *
 * BASIC call flow:
 *
 * ALICE                        BOB
 *      | invite -->            |
 *      |           <-- ringing |
 *      |          <-- starting |
 *      | started -->           |
 *      | <-- MEDIA TRANS -->   |
 *      | ending -->            |
 *      |             <-- ended |
 *
 * Alice calls Bob by sending invite packet.
 * Bob recvs the packet and sends an ringing packet;
 * which notifies Alice that her invite is acknowledged.
 * Ringing screen shown on both sides.
 * Bob accepts the invite for a call by sending starting packet.
 * Alice recvs the starting packet and sends the started packet to
 * inform Bob that she recved the starting packet.
 * Now the media transmission is established ( i.e. RTP transmission ).
 * Alice hangs up and sends ending packet.
 * Bob recves the ending packet and sends ended packet
 * as the acknowledgement that the call is ended.
 *
 *
 */
void* media_session_pool_stack(void* _session);
/*------------------------*/

media_session_t* media_init_session ( IP_Port _to_dest );
int media_terminate_session(media_session_t* _session);

/* Registering callbacks */

void media_session_register_callback_send(int (*callback) ( int, uint8_t*, uint16_t ) );

/* It's a function to register as a callback when the ringing state hits on */
void media_session_register_callback_state_ringing(int (*callback) (void));

/* -------- */



/* Function handling receiving from core */
int media_session_handlepacket ( media_session_t* _session, uint8_t* _data, uint16_t _lenght );


#endif /* _RTP__SESSION__INITIATION_H_ */
