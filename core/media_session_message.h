

#ifndef _MEDIA__SESSION__MESSAGE_H_
#define _MEDIA__SESSION__MESSAGE_H_

#include <inttypes.h>

#define TYPE_REQUEST 1
#define TYPE_RESPONSE 0

typedef enum {
    _no_request = 0,
    _invite,
    _start,
    _cancel,
    _reject,
    _end,

} media_request_t;

typedef enum {
    _no_response,
    _trying,
    _ringing,
    _starting,
    _ending,

} media_response_t;

typedef struct media_msg_header_friendid_s /* example of a header */
{
    int _data;

} media_msg_header_friendid_t;

typedef struct media_msg_header_s /* template for a header ( will not implement for now ) */
{
    uint16_t _header_id;
    uint16_t _lenght;

    uint8_t* _data;

    struct media_msg_header_s* next;

} media_msg_header_t;

typedef struct media_msg_s
{
    media_request_t _request;
    media_response_t _response;

    /* Here headers can be added describing the session */
    media_msg_header_t* _headers;

    struct media_msg_s* next;

} media_msg_t;

media_msg_t* media_msg_parse_incomming (int _friendid, uint8_t* _data, int _length);

media_msg_t* media_msg_new ( uint8_t _type, uint8_t _typeid );

uint8_t* media_msg_to_string ( media_msg_t* _msg );

#endif /* _MEDIA__SESSION__MESSAGE_H_ */
