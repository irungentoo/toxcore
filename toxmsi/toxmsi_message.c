/* toxmsi_message.c
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*----------------------------------------------------------------------------------*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxmsi_message.h"
#include <stdlib.h>
#include <string.h>
#include "../toxrtp/toxrtp_helper.h"
#include <assert.h>
#include <stdlib.h>

#define ALLOCATE_HEADER(_header_type, _var, _m_header_value) \
_var = calloc( sizeof(_header_type), 1 );                    \
assert(_var);                                                \
_var->_header_value = t_strallcpy((const uint8_t*)_m_header_value);

#define DEALLOCATE_HEADER(_header)          \
if ( _header && _header->_header_value ) {  \
free( _header->_header_value );             \
free( _header ); }

#define SET_HEADER(_header_type, _var, _m_header_value) \
if ( _var ){                                \
free(_var->_header_value);                  \
free(_var);}                                \
ALLOCATE_HEADER( _header_type, _var, _m_header_value )


/* Sets empty message
 */
void set_msg ( msi_msg_t* _msg )
{
    _msg->_call_type = NULL;
    _msg->_version = NULL;
    _msg->_request = NULL;
    _msg->_response = NULL;
    _msg->_friend_id = NULL;
    _msg->_user_agent = NULL;
    _msg->_call_id = NULL;
    _msg->_reason = NULL;
    _msg->_info = NULL;
    _msg->_next = NULL;
    _msg->_headers = NULL;
}

void msi_free_msg ( msi_msg_t* _msg )
{
    assert(_msg);

    DEALLOCATE_HEADER(_msg->_call_type);
    DEALLOCATE_HEADER(_msg->_friend_id);
    DEALLOCATE_HEADER(_msg->_request);
    DEALLOCATE_HEADER(_msg->_response);
    DEALLOCATE_HEADER(_msg->_user_agent);
    DEALLOCATE_HEADER(_msg->_version);
    DEALLOCATE_HEADER(_msg->_info);
    DEALLOCATE_HEADER(_msg->_reason);
    DEALLOCATE_HEADER(_msg->_call_id);

    free(_msg);
}

void append_header_to_string ( uint8_t* _dest, const uint8_t* _header_field, const uint8_t* _header_value )
{
    assert(_dest);
    assert(_header_value);
    assert(_header_field);

    size_t _dest_len = t_memlen(_dest);

    uint8_t* _storage_iterator = _dest + _dest_len;
    const uint8_t* _header_fit = _header_field;
    const uint8_t* _header_val = _header_value;
    const uint8_t* _term_it    = (const uint8_t*) _RAW_TERMINATOR;

    while ( *_header_fit ){
        *_storage_iterator = *_header_fit;
        ++_header_fit;
        ++_storage_iterator;
    }

    *_storage_iterator = ' '; /* place space */
    ++_storage_iterator;

    while ( *_header_val ){
        *_storage_iterator = *_header_val;
        ++_header_val;
        ++_storage_iterator;
    }

    while ( *_term_it ){
        *_storage_iterator = *_term_it;
        ++_term_it;
        ++_storage_iterator;
    }
}

msi_msg_t* msi_parse_msg ( const uint8_t* _data )
{
    assert(_data);

    msi_msg_t* _retu = calloc ( sizeof ( msi_msg_t ), 1 );
    assert(_retu);

    set_msg(_retu);

    _retu->_headers = msi_parse_raw_data ( _data );

    if ( msi_parse_headers (_retu) == FAILURE ) {
        msi_free_msg(_retu);
        return NULL;
    }

    if ( !_retu->_version || strcmp((const char*)_retu->_version->_header_value, VERSION_STRING) != 0 ){
        msi_free_msg(_retu);
        return NULL;
    }

    return _retu;
}


uint8_t* msi_msg_to_string ( msi_msg_t* _msg )
{
    assert(_msg);

    uint8_t* _retu = calloc(sizeof(uint8_t), MSI_MAXMSG_SIZE );
    assert(_retu);

    t_memset(_retu, '\0', MSI_MAXMSG_SIZE);

    if ( _msg->_version ){
        append_header_to_string(_retu, (const uint8_t*)_VERSION_FIELD,      _msg->_version->_header_value);
    }

    if ( _msg->_request ){
        append_header_to_string(_retu, (const uint8_t*)_REQUEST_FIELD,      _msg->_request->_header_value);
    }

    if ( _msg->_response ){
        append_header_to_string(_retu, (const uint8_t*)_RESPONSE_FIELD,     _msg->_response->_header_value);
    }

    if ( _msg->_friend_id ){
        append_header_to_string(_retu, (const uint8_t*)_FRIENDID_FIELD,     _msg->_friend_id->_header_value);
    }

    if ( _msg->_call_type ){
        append_header_to_string(_retu, (const uint8_t*)_CALLTYPE_FIELD,     _msg->_call_type->_header_value);
    }

    if ( _msg->_user_agent ){
        append_header_to_string(_retu, (const uint8_t*)_USERAGENT_FIELD,    _msg->_user_agent->_header_value);
    }

    if ( _msg->_info ){
        append_header_to_string(_retu, (const uint8_t*)_INFO_FIELD,         _msg->_info->_header_value);
    }

    if ( _msg->_call_id ){
        append_header_to_string(_retu, (const uint8_t*)_CALL_ID_FIELD,      _msg->_call_id->_header_value);
    }

     if ( _msg->_reason ){
        append_header_to_string(_retu, (const uint8_t*)_REASON_FIELD,       _msg->_reason->_header_value);
    }

    return _retu;
}

msi_msg_t* msi_msg_new ( uint8_t _type, const uint8_t* _typeid )
{
    msi_msg_t* _retu = calloc ( sizeof ( msi_msg_t ), 1 );
    assert(_retu);

    set_msg(_retu);

    if ( _type == TYPE_REQUEST ){
        ALLOCATE_HEADER( msi_header_request_t, _retu->_request, _typeid )
        _retu->_response = NULL;

    } else if ( _type == TYPE_RESPONSE ) {
        ALLOCATE_HEADER( msi_header_response_t, _retu->_response, _typeid )
        _retu->_request = NULL;

    } else {
        msi_free_msg(_retu);
        return NULL;
    }


    ALLOCATE_HEADER( msi_header_version_t, _retu->_version, VERSION_STRING)

    _retu->_friend_id = NULL;
    _retu->_call_type = NULL;
    _retu->_user_agent = NULL;
    _retu->_info = NULL;

    _retu->_next = NULL;

    return _retu;
}

uint8_t* msi_genterate_call_id  ( uint8_t* _storage, size_t _len )
{
    assert(_storage);

    static const char _alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"; /* avoids warning */

    uint8_t _val = 0;
    size_t _it;

    /* Generate random values 1-255 */
    for ( _it = 0; _it < _len; _it ++ ) {
        while ( !_val ) _val = (uint8_t) _alphanum[ t_random(61) ];

        _storage[_it] = _val;
        _val = 0;
    }

    return _storage;
}

/* HEADER SETTING
 */

void msi_msg_set_call_type  ( msi_msg_t* _msg, const uint8_t* _header_field )
{
    assert(_msg);
    assert(_header_field);

    SET_HEADER(msi_header_call_type_t, _msg->_call_type, _header_field)
}
void msi_msg_set_user_agent ( msi_msg_t* _msg, const uint8_t* _header_field )
{
    assert(_msg);
    assert(_header_field);

    SET_HEADER(msi_header_user_agent_t, _msg->_user_agent, _header_field)
}
void msi_msg_set_friend_id  ( msi_msg_t* _msg, const uint8_t* _header_field )
{
    assert(_msg);
    assert(_header_field);

    SET_HEADER(msi_header_friendid_t, _msg->_friend_id, _header_field)
}
void msi_msg_set_info ( msi_msg_t* _msg, const uint8_t* _header_field )
{
}
void msi_msg_set_reason ( msi_msg_t* _msg, const uint8_t* _header_field )
{
    assert(_msg);
    assert(_header_field);

    SET_HEADER(msi_header_reason_t, _msg->_reason, _header_field)
}
void msi_msg_set_call_id ( msi_msg_t* _msg, const uint8_t* _header_field )
{
    assert(_msg);
    assert(_header_field);

    SET_HEADER(msi_header_call_id_t, _msg->_call_id, _header_field)
}
