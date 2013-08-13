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


#ifndef _MEDIA__SESSION__INITIATION_H_
#define _MEDIA__SESSION__INITIATION_H_

#include <inttypes.h>
#include "Messenger.h"
#include "../Tuxrtp/rtp_impl.h"
#include <pthread.h>
#include "media_session_message.h"

#define STATE_CALLBACK_ARGS void
#define STATE_CALLBACK int (*callback) (STATE_CALLBACK_ARGS)

size_t m_strlen ( uint8_t* str );

typedef enum
{
    call_active,
    call_hold,
    call_ended

} call_state;

typedef struct media_session_s {
    rtp_session_t* _rtp_session;


    pthread_t _thread_id;

    media_msg_t* _msg_list;
    int _friend_id;

    int _last_request; /* It determines if state was active */
    int _last_response; /* Same here */

    call_state _call_info;

    /* Martijnvdc add your media stuff here so this will be used in messenger */

} media_session_t;

/* OUR MAIN POOL FUNCTION */
/*
 * Forks it self to other thread and then handles the session initiation.
 *
 * BASIC call flow:
 *
 *    ALICE                    BOB
 *      | invite -->            |
 *      |                       |
 *      |           <-- ringing |
 *      |                       |
 *      |          <-- starting |
 *      |                       |
 *      | start -->             |
 *      |                       |
 *      |  <-- MEDIA TRANS -->  |
 *      |                       |
 *      | end -->               |
 *      |                       |
 *      |            <-- ending |
 *
 * Alice calls Bob by sending invite packet.
 * Bob recvs the packet and sends an ringing packet;
 * which notifies Alice that her invite is acknowledged.
 * Ringing screen shown on both sides.
 * Bob accepts the invite for a call by sending starting packet.
 * Alice recvs the starting packet and sends the started packet to
 * inform Bob that she recved the starting packet.
 * Now the media transmission is established ( i.e. RTP transmission ).
 * Alice hangs up and sends end packet.
 * Bob recves the end packet and sends ending packet
 * as the acknowledgement that the call is ending.
 *
 *
 */
void* media_session_pool_stack(void* _session);
/*------------------------*/

media_session_t* media_init_session ( IP_Port _to_dest );
int media_terminate_session(media_session_t* _session);

/* Registering callbacks */

void media_session_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) );

/* Callbacks that handle the states */
void media_session_register_callback_recv_invite(STATE_CALLBACK);
void media_session_register_callback_call_started(STATE_CALLBACK);
void media_session_register_callback_call_canceled(STATE_CALLBACK);
void media_session_register_callback_call_rejected(STATE_CALLBACK);
void media_session_register_callback_call_ended(STATE_CALLBACK);

void media_session_register_callback_recv_trying(STATE_CALLBACK);
void media_session_register_callback_recv_ringing(STATE_CALLBACK);
void media_session_register_callback_recv_starting(STATE_CALLBACK);
void media_session_register_callback_recv_ending(STATE_CALLBACK);
/* -------- */


/* Function handling receiving from core */
/*static int media_session_handlepacket ( IP_Port ip_port, uint8_t* _data, uint16_t _lenght ); */


int media_session_invite ( media_session_t* _session );
int media_session_answer ( media_session_t* _session );
int media_session_hangup ( media_session_t* _session );


#endif /* _MEDIA__SESSION__INITIATION_H_ */
