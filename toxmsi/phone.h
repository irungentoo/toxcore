#ifndef _PHONE_H_
#define _PHONE_H_

#include "msi_impl.h"
#include "msi_message.h"
#include "../toxrtp/rtp_message.h"
#include "../toxrtp/tests/test_helper.h"
#include <assert.h>

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

    pthread_id _medialoop_id;

    Networking_Core* _networking;
} phone_t;

phone_t* initPhone(uint16_t _listen_port, uint16_t _send_port);
int      quitPhone(phone_t* _phone);

/* My recv functions */
int rtp_handlepacket ( rtp_session_t* _session, rtp_msg_t* _msg );
int msi_handlepacket ( msi_session_t* _session, tox_IP_Port ip_port, uint8_t* data, uint32_t length );

/* This is basically representation of networking_poll of toxcore */
void* phone_receivepacket ( void* _phone );

/* Phones main loop */
void* phone_poll ( void* _phone );

pthread_t phone_startmain_loop(phone_t* _phone);
pthread_t phone_startmedia_loop ( phone_t* _phone );

/* Thread handlers */
void* phone_handle_receive_callback ( void* _p );
void* phone_handle_media_transport_poll ( void* _hmtc_args_p );


/* msi callbacks */
MCBTYPE phone_callback_recv_invite ( MCBARGS );
MCBTYPE phone_callback_recv_trying ( MCBARGS );
MCBTYPE phone_callback_recv_ringing ( MCBARGS );
MCBTYPE phone_callback_recv_starting ( MCBARGS );
MCBTYPE phone_callback_recv_ending ( MCBARGS );

MCBTYPE phone_callback_call_started ( MCBARGS );
MCBTYPE phone_callback_call_canceled ( MCBARGS );
MCBTYPE phone_callback_call_rejected ( MCBARGS );
MCBTYPE phone_callback_call_ended ( MCBARGS );

#endif /* _PHONE_H_ */
