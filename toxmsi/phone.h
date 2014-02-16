/* phone.h
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
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

/*----------------------------------------------------------------------------------*/

#ifndef _PHONE_H_
#define _PHONE_H_

#include "toxmsi.h"
#include "../toxrtp/toxrtp.h"
#include "toxmsi_message.h"
#include "../toxrtp/toxrtp_message.h"
#include "../toxrtp/tests/test_helper.h"
#include <assert.h>
#include <pthread.h>
#include "toxmedia.h"

/* Define client version */
#define _USERAGENT "tox_phone-v.0.2.1"

static pthread_mutex_t _mutex;

#define THREADLOCK() \
pthread_mutex_lock ( &_mutex );

#define THREADUNLOCK() \
pthread_mutex_unlock ( &_mutex );

typedef struct phone_s {
    msi_session_t* _msi;

    rtp_session_t* _rtp_audio;
    rtp_session_t* _rtp_video;

    uint32_t _frame_rate;

    uint16_t _send_port, _recv_port;

    int _tox_sock;

    pthread_t _medialoop_id;
    codec_state *cs;

    Networking_Core* _networking;
} phone_t;

phone_t* initPhone(uint16_t _listen_port, uint16_t _send_port);
int      quitPhone(phone_t* _phone);

/* My recv functions */
int rtp_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length );
int msi_handlepacket ( void* _object, tox_IP_Port ip_port, uint8_t* data, uint32_t length );

/* This is basically representation of networking_poll of toxcore */
void* phone_receivepacket ( void* _phone );

/* Phones main loop */
void* phone_poll ( void* _phone );

pthread_t phone_startmain_loop(phone_t* _phone);
pthread_t phone_startmedia_loop ( phone_t* _phone );

/* Thread handlers */
void* phone_handle_receive_callback ( void* _p );
void* phone_handle_media_transport_poll ( void* _hmtc_args_p );

#endif /* _PHONE_H_ */
