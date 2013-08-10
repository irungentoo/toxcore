#include "media_session_initiation.h"
#include "../core/net_crypto.h"
#include "../core/Lossless_UDP.h"

#include <assert.h>


/* --------- GLOBAL FUNCTIONS USED BY THIS FILE --------- */

/* CALLBACKS */
int (*media_session_send_message_callback) ( int, uint8_t*, uint16_t ) = NULL;

int (*media_session_state_ringing_callback) (void) = NULL;
/* End of CALLBACKS */

/* --------- END OF GLOBAL FUNCTIONS USED BY THIS FILE --------- */

media_session_t* media_init_session(IP_Port _to_dest)
{
    media_session_t* _retu = malloc ( sizeof ( media_session_t ) );

    _retu->_rtp_session = rtp_init_session(_to_dest, -1);
    _retu->_last_recv_state = _none;

    return _retu;
}

int media_terminate_session(media_session_t* _session)
{
    int status;

    if ( !_session )
        return -1;

    status = rtp_terminate_session(_session->_rtp_session);
    free(_session);

    /* Session termination etc... */

    return status;
}

void media_session_register_callback_send(int (*callback) ( int, uint8_t*, uint32_t ) )
{
    media_session_send_message_callback = callback;
}

void media_session_register_callback_state_ringing(int (*callback) (void))
{
    media_session_state_ringing_callback = callback;
}

int media_session_handle_recv_invite ( media_session_t* _session, uint8_t* _data, uint16_t _lenght )
{
}
int media_session_handle_recv_ringing ( media_session_t* _session, uint8_t* _data, uint16_t _lenght )
{
}

int media_session_handlepacket ( media_session_t* _session, uint8_t* _data, uint16_t _lenght )
{
    assert(0);
    if ( _lenght < 2 )
        return FAILURE;

    if ( _data[1] > 10 )
        return FAILURE; /* Not a state msg */

    _session->_last_recv_state = _data[1];

    return 1; /* Core adaptation */
}

void* media_session_pool_stack(void* _session)
{
    printf("\n Call started!\n");
    return NULL;
}
