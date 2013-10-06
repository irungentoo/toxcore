#ifndef _MSI_MESSAGE_H_
#define _MSI_MESSAGE_H_

#include <inttypes.h>
#include "network.h"
#include "tox.h"

#include "msi_header.h"

#define TYPE_REQUEST 1
#define TYPE_RESPONSE 2

#define VERSION_STRING "0.1.1"

#define MSI_MAXMSG_SIZE 1024

typedef enum {
    _invite,
    _start,
    _cancel,
    _reject,
    _end,

} msi_request_t;
/**/
static inline const uint8_t *stringify_request(msi_request_t _request)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"INVITE",
        (uint8_t*)"START",
        (uint8_t*)"CANCEL",
        (uint8_t*)"REJECT",
        (uint8_t*)"END"
    };

    return strings[_request];
}

typedef enum {
    _trying,
    _ringing,
    _starting,
    _ending,

} msi_response_t;

/**/
static inline const uint8_t *stringify_response(msi_response_t _response)
{
    static const uint8_t* strings[] =
    {
        (uint8_t*)"trying",
        (uint8_t*)"ringing",
        (uint8_t*)"starting",
        (uint8_t*)"ending"
    };

    return strings[_response];
}


typedef struct msi_msg_s {
    /* This is the header list which contains unparsed headers */
    msi_header_t* _headers;

    /* Headers parsed */
    msi_header_version_t* _version;
    msi_header_request_t* _request;
    msi_header_response_t* _response;
    msi_header_friendid_t* _friend_id;
    msi_header_call_type_t* _call_type;
    msi_header_user_agent_t* _user_agent;
    msi_header_info_t* _info;

    /* Pointer to next member since it's list duuh */
    struct msi_msg_s* _next;

} msi_msg_t;


/*
 * Parse data received from socket
 */
msi_msg_t*      msi_parse_msg          ( const uint8_t* _data );

/*
 * Make new message. Arguments: _type: (request, response); _type_field ( value )
 */
msi_msg_t*      msi_msg_new            ( uint8_t _type, const uint8_t* _type_field );

/* Header setting */
int             msi_msg_set_call_type  ( msi_msg_t* _msg, const uint8_t* _type_field );
int             msi_msg_set_user_agent ( msi_msg_t* _msg, const uint8_t* _type_field );
int             msi_msg_set_friend_id  ( msi_msg_t* _msg, const uint8_t* _type_field );

/*
 * Parses message struct to string.
 * Allocates memory so don't forget to free it
 */
uint8_t*        msi_msg_to_string      ( msi_msg_t* _msg );

/*
 * msi_msg_s struct deallocator
 */
void            msi_free_msg           ( msi_msg_t* _msg );

#endif /* _MSI_MESSAGE_H_ */
