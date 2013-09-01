/* msi_initiation.h
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


#ifndef _MSI_IMPL_H_
#define _MSI_IMPL_H_

#include <inttypes.h>
#include "rtp_impl.h"
#include "tox.h"
#include <pthread.h>

#define MCBARGS void
#define MCBTYPE int
#define MCALLBACK MCBTYPE (*callback) (MCBARGS)

#define MSI_PACKET 69

size_t m_strlen ( uint8_t* str );

typedef enum {
    call_inviting,
    call_active,
    call_hold,
    call_ended

} call_state;

typedef struct media_session_s {
    rtp_session_t* _rtp_audio;
    rtp_session_t* _rtp_video;


    pthread_t _thread_id;

    struct media_msg_s* _oldest_msg;
    struct media_msg_s* _last_msg; /* tail */
    /*int _friend_id;*/
    tox_IP_Port _friend_id;

    int _last_request; /* It determines if state was active */
    int _last_response; /* Same here */

    call_state _call_info;

    int _socket;

    uint8_t  _call_type;
    uint32_t _frame_rate;

    /* Martijnvdc add your media stuff here so this will be used in messenger */

} media_session_t;



media_session_t* msi_init_session ( int _socket );
int msi_terminate_session ( media_session_t* _session );

int msi_start_main_loop ( media_session_t* _session );

/* Registering callbacks */

/*void msi_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) );*/
void msi_register_callback_send ( int ( *callback ) ( int _socket, tox_IP_Port,  uint8_t*, uint32_t ) );

/* Callbacks that handle the states */
void msi_register_callback_call_started ( MCALLBACK );
void msi_register_callback_call_canceled ( MCALLBACK );
void msi_register_callback_call_rejected ( MCALLBACK );
void msi_register_callback_call_ended ( MCALLBACK );

void msi_register_callback_recv_invite ( MCALLBACK );
void msi_register_callback_recv_trying ( MCALLBACK );
void msi_register_callback_recv_ringing ( MCALLBACK );
void msi_register_callback_recv_starting ( MCALLBACK );
void msi_register_callback_recv_ending ( MCALLBACK );
/* -------- */


/* Function handling receiving from core */
/*static int msi_handlepacket ( tox_IP_Port ip_port, uint8_t* _data, uint16_t _lenght ); */


int msi_invite ( media_session_t* _session );
int msi_hangup ( media_session_t* _session );

int msi_answer ( media_session_t* _session );
int msi_cancel ( media_session_t* _session );
int msi_reject ( media_session_t* _session );


#endif /* _MSI_IMPL_H_ */
