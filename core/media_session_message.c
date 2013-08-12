#include "media_session_message.h"
#include <malloc.h>

media_msg_t* media_msg_parse_incomming (int _friendid, uint8_t* _data, int _length)
{
    if ( _length < 2 )
        return NULL;

    media_msg_t* _retu = malloc(sizeof(media_msg_t));

    uint8_t* _it = _data;

    if ( *_it == TYPE_REQUEST ) { /* Handle request */
        ++ _it;
        _retu->_request = *_it;
        _retu->_response = _no_response;
    }
    else { /* Handle response */
        ++ _it;
        _retu->_response = *_it;
        _retu->_request = _no_request;
    }

    _retu->_headers = NULL;

    _retu->next = NULL;

    return _retu;
}

media_msg_t* media_msg_new ( uint8_t _type, uint8_t _typeid )
{
    media_msg_t* _retu = malloc(sizeof(media_msg_t));

    if ( _type == TYPE_REQUEST ) { /* Handle request */
        _retu->_request = _typeid;
        _retu->_response = _no_response;
    }
    else { /* Handle response */
        _retu->_response = _typeid;
        _retu->_request = _no_request;
    }

    _retu->_headers = NULL;

    _retu->next = NULL;

    return _retu;
}

uint8_t* media_msg_to_string ( media_msg_t* _msg )
{
    uint8_t* _retu = malloc( 3 ); /* i wonder how will i take care of this */

    if ( _msg->_request != _no_request ){
        _retu [0] = TYPE_REQUEST;
        _retu [1] = _msg->_request;
    }
    else {
        _retu [0] = TYPE_RESPONSE;
        _retu [1] = _msg->_response;
    }

    _retu[2] = '\0';

    return _retu;
}
