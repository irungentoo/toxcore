#ifndef _HANDLER_H_
#define _HANDLER_H_

#include "rtp_impl.h"
#include "../core/helper.h"


int             rtp_add_user ( rtp_session_t* _session, IP_Port _dest );
int             rtp_send_msg ( rtp_session_t* _session, rtp_msg_t* msg );
int             rtp_recv_msg ( rtp_session_t* _session ); /* function made for threading */
rtp_msg_t*      rtp_msg_new  ( rtp_session_t* _session, uint8_t* _data, uint32_t _length, IP_Port* _from );

#endif /* _HANDLER_H_ */
