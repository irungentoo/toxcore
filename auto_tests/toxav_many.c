#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include "../toxcore/tox.h"
#include "../toxcore/logger.h"
#include "../toxav/toxav.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif



typedef enum _CallStatus {
    none,
    InCall,
    Ringing,
    Ended,
    Rejected,
    Cancel
    
} CallStatus;

typedef struct _Party {
    CallStatus status;
    ToxAv *av;
    time_t *CallStarted;
    int call_index;
} Party;

typedef struct _Status {
    Party Alice;
    Party Bob;
} Status;

void accept_friend_request(Tox *m, uint8_t *public_key, uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/******************************************************************************/
void callback_recv_invite ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Ringing;
    cast->call_index = call_index;
}
void callback_recv_ringing ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Ringing;
}
void callback_recv_starting ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = InCall;
    toxav_prepare_transmission(cast->av, call_index, 1);
}
void callback_recv_ending ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Ended;
}

void callback_recv_error ( uint32_t call_index, void *_arg )
{
    ck_assert_msg(0, "AV internal error");
}

void callback_call_started ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = InCall;
    toxav_prepare_transmission(cast->av, call_index, 1);
}
void callback_call_canceled ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Cancel;
}
void callback_call_rejected ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Rejected;
}
void callback_call_ended ( uint32_t call_index, void *_arg )
{
    Party *cast = _arg;
    
    cast->status = Ended;
}

void callback_requ_timeout ( uint32_t call_index, void *_arg )
{
    ck_assert_msg(0, "No answer!");
}
/*************************************************************************************************/
