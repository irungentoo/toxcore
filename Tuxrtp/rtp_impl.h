#ifndef _RTP__IMPL_H_
#define _RTP__IMPL_H_

#include "Allocator.h"
#include "rtp_message.h"

#define WINDOWS WIN32 || WIN64
#define _RTP_VERSION_ 2

typedef struct rtp_dest_list_s {
    IP_Port                 _dest;
    struct rtp_dest_list_s* next;
    /* int con_id; */

    } rtp_dest_list_t;



typedef struct rtp_session_s {
    uint8_t                 _version;
    uint8_t                 _padding;
    uint8_t                 _extension;
    uint8_t                 _cc;
    uint8_t                 _marker;
    uint8_t                 _payload_type;
    uint16_t                _sequence_number;
    uint16_t                _initial_time;
    uint32_t                _time_elapsed;
    uint32_t                _ssrc;
    uint32_t                _csrc;

    rtp_ext_header_t*       _ext_header; /* If some additional data must be sent via message
                                          * apply it here. Only by allocating this member you will be
                                          * automatically placing it within a message.
                                          */

    int                     _max_users;    /* -1 undefined */

    unsigned int            _packets_sent; /* measure packets */
    unsigned int            _packets_recv;

    unsigned int            _bytes_sent;
    unsigned int            _bytes_recv;

    const char*             _last_error;

    struct rtp_dest_list_s* _dest_list;
    struct rtp_dest_list_s* _last_user; /* a tail for faster appending */

    struct rtp_msg_s*       _messages;
    struct rtp_msg_s*       _last_msg;

    } rtp_session_t;


rtp_session_t*  rtp_init_session ( IP_Port _dest, int max_users ); /* you need to have at least 1 receiver */
rtp_msg_t*      rtp_session_get_message_queded ( rtp_session_t* _session );

uint8_t LAST_SOCKET_DATA[MAX_UDP_PACKET_SIZE];

#endif /* _RTP__IMPL_H_ */
