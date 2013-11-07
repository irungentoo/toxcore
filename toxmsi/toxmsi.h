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
#include "tox.h"
#include <pthread.h>

#define MCBTYPE void
#define MCBARGS void* _arg
#define MCALLBACK MCBTYPE(*callback)(void* _arg)

#define MSI_PACKET 69

#define CT_AUDIO_HEADER_VALUE "AUDIO"
#define CT_VIDEO_HEADER_VALUE "VIDEO"

/* define size for call_id */
#define _CALL_ID_LEN 12

typedef enum {
    type_audio = 1,
    type_video,
} call_type;

typedef enum {
    call_inviting, /* when sending call invite */
    call_starting, /* when getting call invite */
    call_active,
    call_hold

} call_state;

typedef int crypto_key;

typedef struct msi_call_s {         /* Call info structure */
    call_state  _state;
    call_type   _type_local;
    call_type  *_type_peer;         /* Support for conference starts with this */
    uint8_t     _id[_CALL_ID_LEN];  /* Random value identifying the call */
    crypto_key  _key;               /* What is the type again? */
    uint16_t    _participants;      /* Number of participants */
    uint32_t    _timeoutst;         /* Time of the timeout for some action to end; 0 if infinite */
    int         _outgoing_timer_id; /* Timer id */

} msi_call_t;

typedef struct msi_session_s {
    pthread_mutex_t _mutex;

    crypto_key _key; /* The key */

    /* Call information/handler. ( Maybe only information? ) */
    msi_call_t *_call;

    /* Storage for message receiving */
    struct msi_msg_s *_oldest_msg;
    struct msi_msg_s *_last_msg; /* tail */

    /*int _friend_id;*/
    tox_IP_Port _friend_id;

    int             _last_error_id; /* Determine the last error */
    const uint8_t  *_last_error_str;

    const uint8_t *_user_agent;

    void *_agent_handler;   /* Pointer to an object that is handling msi */
    void *_core_handler;    /* Pointer to networking core or to anything that
                             * should handle interaction with core/networking
                             */
    void *_event_handler;   /* Pointer to an object which handles the events */

    uint32_t _frequ;
    uint32_t _call_timeout; /* Time of the timeout for some action to end; 0 if infinite */
} msi_session_t;



msi_session_t *msi_init_session ( void *_core_handler, const uint8_t *_user_agent );
int msi_terminate_session ( msi_session_t *_session );

pthread_t msi_start_main_loop ( msi_session_t *_session, uint32_t _frequms );

/* Registering callbacks */

/*void msi_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) );*/
void msi_register_callback_send ( int ( *callback ) ( void *_core_handler, tox_IP_Port,  uint8_t *, uint32_t ) );

/* Callbacks that handle the states */
void msi_register_callback_call_started ( MCALLBACK );
void msi_register_callback_call_canceled ( MCALLBACK );
void msi_register_callback_call_rejected ( MCALLBACK );
void msi_register_callback_call_ended ( MCALLBACK );

void msi_register_callback_recv_invite ( MCALLBACK );
void msi_register_callback_recv_ringing ( MCALLBACK );
void msi_register_callback_recv_starting ( MCALLBACK );
void msi_register_callback_recv_ending ( MCALLBACK );
void msi_register_callback_recv_error ( MCALLBACK );

void msi_register_callback_requ_timeout ( MCALLBACK );
/* -------- */


/* Function handling receiving from core */
/*static int msi_handlepacket ( tox_IP_Port ip_port, uint8_t* _data, uint16_t _lenght ); */

/* functions describing the usage of msi */
int msi_invite ( msi_session_t *_session, call_type _call_type, uint32_t _timeoutms );
int msi_hangup ( msi_session_t *_session );

int msi_answer ( msi_session_t *_session, call_type _call_type );
int msi_cancel ( msi_session_t *_session );
int msi_reject ( msi_session_t *_session );

int  msi_send_msg ( msi_session_t *_session, struct msi_msg_s *_msg );
void msi_store_msg ( msi_session_t *_session, struct msi_msg_s *_msg );

#endif /* _MSI_IMPL_H_ */
