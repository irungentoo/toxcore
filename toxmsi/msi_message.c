#include "msi_message.h"
#include <malloc.h>
#include <string.h>
#include "../toxrtp/rtp_helper.h"
#include <assert.h>

#define ALLOCATE_HEADER(_header_type, _var, _m_header_value) \
_var = malloc( sizeof(_header_type) ); \
_var->_header_value = t_strallcpy((const uint8_t*)_m_header_value);

#define DEALLOCATE_HEADER(_header) \
if ( _header && _header->_header_value ) {\
free( _header->_header_value ); \
free( _header ); \
}

/* Sets empty message
 * ?or should i use memset?
 */
void set_msg ( msi_msg_t* _msg )
{
    _msg->_call_type = NULL;
    _msg->_version = NULL;
    _msg->_request = NULL;
    _msg->_response = NULL;
    _msg->_friend_id = NULL;
    _msg->_user_agent = NULL;
    _msg->_info = NULL;
    _msg->_next = NULL;
    _msg->_headers = NULL;
}

void append_header_to_string ( uint8_t* _dest, const uint8_t* _header_field, const uint8_t* _header_value )
{
    if ( !_header_value || !_header_field ){
        return;
    }
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
    if ( !_data ){
        return NULL;
    }

    msi_msg_t* _retu = malloc ( sizeof ( msi_msg_t ) );
    set_msg(_retu);

    _retu->_headers = msi_parse_raw_data ( (uint8_t*)_data );

    if ( msi_parse_headers (_retu) == FAILURE ) {
        msi_free_msg(_retu);
        return NULL;
    }

    return _retu;
}

msi_msg_t* msi_msg_new ( uint8_t _type, const uint8_t* _typeid )
{
    msi_msg_t* _retu = malloc ( sizeof ( msi_msg_t ) );
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

int msi_msg_set_call_type  ( msi_msg_t* _msg, const uint8_t* _type_field )
{
    if ( !_msg || !_type_field )
        return FAILURE;

    if ( _msg->_call_type ){ /* already there */
        free(_msg->_call_type->_header_value);
        free(_msg->_call_type);
    }
    ALLOCATE_HEADER( msi_header_call_type_t, _msg->_call_type, _type_field )


    return SUCCESS;
}
int msi_msg_set_user_agent ( msi_msg_t* _msg, const uint8_t* _type_field )
{
    if ( !_msg || !_type_field  )
        return FAILURE;

    if ( _msg->_user_agent ){ /* already there */
        free(_msg->_call_type->_header_value);
        free(_msg->_call_type);
    }
    ALLOCATE_HEADER( msi_header_call_type_t, _msg->_call_type, _type_field )

    return SUCCESS;
}
int msi_msg_set_friend_id  ( msi_msg_t* _msg, const uint8_t* _type_field )
{
    if ( !_msg || !_type_field  )
        return FAILURE;

    if ( _msg->_friend_id ){ /* already there */
        free(_msg->_call_type->_header_value);
        free(_msg->_call_type);
    }
    ALLOCATE_HEADER( msi_header_call_type_t, _msg->_call_type, _type_field )

    return SUCCESS;
}

uint8_t* msi_msg_to_string ( msi_msg_t* _msg )
{
    if ( !_msg ){
        return NULL;
    }

    /* got tired of allocating everything dynamically dammit
     * this will do it
     */
    uint8_t* _retu = malloc(sizeof(uint8_t) * MSI_MAXMSG_SIZE );
    t_memset(_retu, '\0', MSI_MAXMSG_SIZE);
    /* So bloody easy... */


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

    return _retu;
}

void msi_free_msg ( msi_msg_t* _msg )
{
    if ( _msg ){
        DEALLOCATE_HEADER(_msg->_call_type);
        DEALLOCATE_HEADER(_msg->_friend_id);
        DEALLOCATE_HEADER(_msg->_request);
        DEALLOCATE_HEADER(_msg->_response);
        DEALLOCATE_HEADER(_msg->_user_agent);
        DEALLOCATE_HEADER(_msg->_version);
        DEALLOCATE_HEADER(_msg->_info);
        free(_msg);
    }
}













