#include "rtp_impl.h"

rtp_session_t* init_rtp_session ( IP_Port _dest, int max_users )
{
    /* con_id = getconnection_id( _dest );
	   if ( con_id == FAILURE )
       return NULL; // cannot establish rtp session if no connection */

    rtp_session_t* _retu;
    ALLOCATOR_S ( _retu, rtp_session_t )
    ALLOCATOR_LIST_S ( _retu->_dest_list, rtp_dest_list_t, NULL )
    _retu->_last_user = _retu->_dest_list; // set tail
    _retu->_dest_list->_dest = _dest;
    _retu->_max_users = max_users;
    _retu->_packets_recv = 0;
    _retu->_packets_sent = 0;
    _retu->_bytes_sent = 0;
    _retu->_bytes_recv = 0;
    _retu->_last_error = NULL;
    _retu->_messages = NULL;
    _retu->_last_msg = NULL;
    memset ( LAST_SOCKET_DATA, '\0', MAX_UDP_PACKET_SIZE );
    return _retu;
}


rtp_msg_t* rtp_session_get_message_queded ( rtp_session_t* _session ) /* I lost faith in this method
																		 and probably will drop it later
 */
{
    rtp_msg_t* queded = _session->_messages; /* you need to get the oldest */
    if ( queded )
        {
            _session->_messages = queded->next;
        }
    return queded;
}
