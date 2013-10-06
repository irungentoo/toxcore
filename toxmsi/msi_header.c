#include "msi_message.h"
#include <string.h>
#include "../toxrtp/rtp_helper.h"
#include "../toxrtp/rtp_allocator.h"
#include <assert.h>
#include "../toxcore/Lossless_UDP.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#define ALLOC_ADD_DATA(_tempval, _hdrlist, _fielddef, _msgvar, _alloctype)    \
_tempval = msi_search_field(_hdrlist, (const uint8_t*)_fielddef);       \
if ( _tempval ){         \
    _msgvar = malloc(sizeof(_alloctype));      \
    _msgvar->_header_value = _tempval;       \
}

uint8_t* msi_search_field ( msi_header_t* _list, const uint8_t* _field )
{
    if ( !_list || !_field ){
        return NULL;
    }

    msi_header_t* _iterator;

    for ( _iterator = _list;
          _iterator && strcmp((const char*)_iterator->_header_field, (const char*)_field) != 0;
          _iterator = _iterator->next );

    if ( _iterator ){
        return t_strallcpy(_iterator->_header_value);
    } else return NULL;
}

int msi_parse_headers ( msi_msg_t* _msg )
{
    if ( !_msg || !(_msg->_headers) )
        return FAILURE;

    msi_header_t* _list = _msg->_headers;
    uint8_t* _field_current;

    /* Start by default order */
    ALLOC_ADD_DATA(_field_current, _list, _VERSION_FIELD, _msg->_version, msi_header_version_t)
    ALLOC_ADD_DATA(_field_current, _list, _REQUEST_FIELD, _msg->_request, msi_header_request_t)
    ALLOC_ADD_DATA(_field_current, _list, _RESPONSE_FIELD, _msg->_response, msi_header_response_t)
    ALLOC_ADD_DATA(_field_current, _list, _FRIENDID_FIELD, _msg->_friend_id, msi_header_friendid_t)
    ALLOC_ADD_DATA(_field_current, _list, _CALLTYPE_FIELD, _msg->_call_type, msi_header_call_type_t)
    ALLOC_ADD_DATA(_field_current, _list, _USERAGENT_FIELD, _msg->_user_agent, msi_header_user_agent_t)
    ALLOC_ADD_DATA(_field_current, _list, _INFO_FIELD, _msg->_info, msi_header_info_t)
    ALLOC_ADD_DATA(_field_current, _list, _REASON_FIELD, _msg->_reason, msi_header_reason_t)
    ALLOC_ADD_DATA(_field_current, _list, _CALL_ID, _msg->_call_id, msi_header_call_id_t)

    /* Since we don't need the raw header anymore remove it */
    msi_header_t* _temp;
    while ( _list ){
        _temp = _list->next;
        free(_list->_header_field);
        free(_list->_header_value);
        free(_list);
        _list = _temp;
    }

    _msg->_headers = NULL;

    return SUCCESS;
}

/*
 * If you find better way of parsing values let me know
 */
msi_header_t* msi_add_new_header ( uint8_t* _value )
{
    if ( !_value )
        return NULL;

    size_t _length = t_memlen(_value);

    if ( !_length ) {
        return NULL;
    }

    size_t _first_len = t_strfind(_value, (const uint8_t*)" ");
    if ( !_first_len ){
        return NULL;
    }

    size_t _second_len = (_length - _first_len);
    if ( !_second_len ){
        return NULL;
    }


    uint8_t* _identifier = malloc(sizeof (uint8_t) * (_first_len + 1) );
    uint8_t* _data = malloc(sizeof (uint8_t) * (_second_len + 1) );


    uint8_t* _p_it = _value;
    size_t _num_it;

    for ( _num_it = 0; *_p_it != ' '; _num_it++ ){
        _identifier[_num_it] = *_p_it;
        ++_p_it;
    }
    _identifier[_num_it] = '\0';
    ++_p_it;


    for ( _num_it = 0; *_p_it != '\r'; _num_it++ ){
        _data[_num_it] = *_p_it;
        ++_p_it;
    }
    _data[_num_it] = '\r';
    _data[_num_it + 1] = '\0';

    msi_header_t* _retu = malloc(sizeof(msi_header_t));

    _retu->_header_field = _identifier;
    _retu->_header_value = _data;
    _retu->next = NULL;

    return _retu;
}

msi_header_t* msi_parse_raw_data ( uint8_t* _data )
{
    if ( !_data ){
        return NULL;
    }

    uint8_t* _header_string;

    _header_string = (uint8_t*) strtok ((char*)_data, _RAW_TERMINATOR);

    msi_header_t* _head = msi_add_new_header(_header_string);
    msi_header_t* _it = _head;

    while ( _header_string && _it ){

        _header_string = (uint8_t*) strtok (NULL, _RAW_TERMINATOR);
        _it->next = msi_add_new_header(_header_string);
        if ( _it->next ){
            _it = _it->next;
        }
    }

    /* Iterate through list and remove all fault headers if any */

    msi_header_t* _tmp = _it;

    for ( _it = _head; _it; _it = _it->next ){

        if ( !_it->_header_value || !_it->_header_field ) {
            _tmp ->next = _it->next;

            if ( _it->_header_field )
                free(_it->_header_field);
            if ( _it->_header_value )
                free(_it->_header_value);

            if ( _it == _head ){
                _head = _head->next;
            }

            free(_it);
            _it = _tmp;
        } else
            _tmp = _it;

    }

    return _head;
}



