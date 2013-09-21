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
#include "../toxrtp/rtp_impl.h"
#include "../toxcore/tox.h"
#include <pthread.h>

#define MCBARGS void* _arg
#define MCBTYPE int
#define MCALLBACK MCBTYPE (*callback) (MCBARGS)

#define MSI_PACKET 69

#define CT_AUDIO_HEADER_VALUE "AUDIO"
#define CT_VIDEO_HEADER_VALUE "VIDEO"


size_t m_strlen ( uint8_t* str );

typedef enum {
    type_audio = 1,
    type_video,
} call_type;

typedef enum {
    call_inviting, /* when sending call invite */
    call_starting, /* when getting call invite */
    call_active,
    call_hold,
    call_inactive

} call_state;

typedef struct msi_session_s {
    pthread_t _thread_id;

    struct msi_msg_s* _oldest_msg;
    struct msi_msg_s* _last_msg; /* tail */
    /*int _friend_id;*/
    tox_IP_Port _friend_id;

    int _last_request; /* It determines if state was active */
    int _last_response; /* Same here */

    call_state _call_info;

    void* _core_handler;

    call_type  _local_call_type;
    call_type  _peer_call_type;

    const uint8_t* _user_agent;

    void* _agent_handler;

} msi_session_t;



msi_session_t* msi_init_session ( void* _core_handler, const uint8_t* _user_agent );
int msi_terminate_session ( msi_session_t* _session );

pthread_t msi_start_main_loop ( msi_session_t* _session );

/* Registering callbacks */

/*void msi_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) );*/
void msi_register_callback_send ( int ( *callback ) ( void* _core_handler, tox_IP_Port,  uint8_t*, uint32_t ) );

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

/* functions describing the usage of msi */
int msi_invite ( msi_session_t* _session, call_type _call_type );
int msi_hangup ( msi_session_t* _session );

int msi_answer ( msi_session_t* _session, call_type _call_type );
int msi_cancel ( msi_session_t* _session );
int msi_reject ( msi_session_t* _session );

int msi_send_msg ( msi_session_t* _session, struct msi_msg_s* _msg );

#endif /* _MSI_IMPL_H_ */
