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
