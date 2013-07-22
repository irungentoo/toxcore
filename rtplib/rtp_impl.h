#ifndef _RTP__IMPL_H_
#define _RTP__IMPL_H_

#include "../core/network.h"
#include "../core/helper.h"
#include "Allocator.h"

#define WINDOWS WIN32 || WIN64

typedef struct rtp_dest_list_s rtp_dest_list_t;
typedef struct rtp_msg_s rtp_msg_t;
typedef struct rtp_session_s rtp_session_t;

struct rtp_dest_list_s
{
    IP_Port     _dest;
    rtp_dest_list_t* next;
    /* int con_id; */

};

struct rtp_msg_s
{
    uint8_t*    _data;
    uint32_t    _length;
    IP_Port     _from;
    rtp_msg_t*  next;
    rtp_msg_t*  prev;
};

struct rtp_session_s
{

    int          _max_users;    /* -1 undefined */

    unsigned int _packets_sent; /* measure packets */
    unsigned int _packets_recv;

    unsigned int _bytes_sent;
    unsigned int _bytes_recv;

    const char*  _last_error;

    rtp_dest_list_t* _dest_list;
    rtp_dest_list_t* _last_user; /* a tail for faster appending */

    rtp_msg_t* _messages;
    rtp_msg_t* _last_msg;

};


rtp_session_t*  rtp_init_session ( IP_Port _dest, int max_users ); /* you need to have at least 1 receiver */
rtp_msg_t*      rtp_session_get_message_queded ( rtp_session_t* _session );

char LAST_SOCKET_DATA[MAX_UDP_PACKET_SIZE];

#endif /* _RTP__IMPL_H_ */
