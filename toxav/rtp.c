/**  rtp.c
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include "rtp.h"
#include <stdlib.h>
void toxav_handle_packet(RTPSession *_session, RTPMessage *_msg);

#define size_32 4

#define ADD_FLAG_VERSION(_h, _v) do { ( _h->flags ) &= 0x3F; ( _h->flags ) |= ( ( ( _v ) << 6 ) & 0xC0 ); } while(0)
#define ADD_FLAG_PADDING(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->flags ) &= 0xDF; ( _h->flags ) |= ( ( ( _v ) << 5 ) & 0x20 ); } while(0)
#define ADD_FLAG_EXTENSION(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->flags ) &= 0xEF;( _h->flags ) |= ( ( ( _v ) << 4 ) & 0x10 ); } while(0)
#define ADD_FLAG_CSRCC(_h, _v) do { ( _h->flags ) &= 0xF0; ( _h->flags ) |= ( ( _v ) & 0x0F ); } while(0)
#define ADD_SETTING_MARKER(_h, _v) do { if ( _v > 1 ) _v = 1; ( _h->marker_payloadt ) &= 0x7F; ( _h->marker_payloadt ) |= ( ( ( _v ) << 7 ) /*& 0x80 */ ); } while(0)
#define ADD_SETTING_PAYLOAD(_h, _v) do { if ( _v > 127 ) _v = 127; ( _h->marker_payloadt ) &= 0x80; ( _h->marker_payloadt ) |= ( ( _v ) /* & 0x7F */ ); } while(0)

#define GET_FLAG_VERSION(_h) (( _h->flags & 0xd0 ) >> 6)
#define GET_FLAG_PADDING(_h) (( _h->flags & 0x20 ) >> 5)
#define GET_FLAG_EXTENSION(_h) (( _h->flags & 0x10 ) >> 4)
#define GET_FLAG_CSRCC(_h) ( _h->flags & 0x0f )
#define GET_SETTING_MARKER(_h) (( _h->marker_payloadt ) >> 7)
#define GET_SETTING_PAYLOAD(_h) ((_h->marker_payloadt) & 0x7f)

/**
 * @brief Checks if message came in late.
 *
 * @param session Control session.
 * @param msg The message.
 * @return int
 * @retval -1 The message came in order.
 * @retval 0 The message came late.
 */
inline__ int check_late_message (RTPSession *session, RTPMessage *msg)
{
    /*
     * Check Sequence number. If this new msg has lesser number then the session->rsequnum
     * it shows that the message came in late. Also check timestamp to be 100% certain.
     *
     */
    return ( msg->header->sequnum < session->rsequnum && msg->header->timestamp < session->timestamp ) ? 0 : -1;
}


/**
 * @brief Extracts header from payload.
 *
 * @param payload The payload.
 * @param length The size of payload.
 * @return RTPHeader* Extracted header.
 * @retval NULL Error occurred while extracting header.
 */
RTPHeader *extract_header ( const uint8_t *payload, int length )
{
    if ( !payload || !length ) {
        LOGGER_WARNING("No payload to extract!");
        return NULL;
    }

    RTPHeader *_retu = calloc(1, sizeof (RTPHeader));

    if ( !_retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    bytes_to_U16(&_retu->sequnum, payload);

    const uint8_t *_it = payload + 2;

    _retu->flags = *_it;
    ++_it;

    /* This indicates if the first 2 bits are valid.
     * Now it may happen that this is out of order but
     * it cuts down chances of parsing some invalid value
     */

    if ( GET_FLAG_VERSION(_retu) != RTP_VERSION ) {
        /* Deallocate */
        LOGGER_WARNING("Invalid version!");
        free(_retu);
        return NULL;
    }

    /*
     * Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t _cc = GET_FLAG_CSRCC ( _retu );
    int _length = 12 /* Minimum header len */ + ( _cc * 4 );

    if ( length < _length ) {
        /* Deallocate */
        LOGGER_WARNING("Length invalid!");
        free(_retu);
        return NULL;
    }

    memset(_retu->csrc, 0, 16 * sizeof (uint32_t));

    _retu->marker_payloadt = *_it;
    ++_it;
    _retu->length = _length;


    bytes_to_U32(&_retu->timestamp, _it);
    _it += 4;
    bytes_to_U32(&_retu->ssrc, _it);

    uint8_t _x;

    for ( _x = 0; _x < _cc; _x++ ) {
        _it += 4;
        bytes_to_U32(&(_retu->csrc[_x]), _it);
    }

    return _retu;
}

/**
 * @brief Extracts external header from payload. Must be called AFTER extract_header()!
 *
 * @param payload The ITERATED payload.
 * @param length The size of payload.
 * @return RTPExtHeader* Extracted extension header.
 * @retval NULL Error occurred while extracting extension header.
 */
RTPExtHeader *extract_ext_header ( const uint8_t *payload, uint16_t length )
{
    const uint8_t *_it = payload;

    RTPExtHeader *_retu = calloc(1, sizeof (RTPExtHeader));

    if ( !_retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    uint16_t _ext_length;
    bytes_to_U16(&_ext_length, _it);
    _it += 2;


    if ( length < ( _ext_length * sizeof(uint32_t) ) ) {
        LOGGER_WARNING("Length invalid!");
        free(_retu);
        return NULL;
    }

    _retu->length  = _ext_length;
    bytes_to_U16(&_retu->type, _it);
    _it += 2;

    if ( !(_retu->table = calloc(_ext_length, sizeof (uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(_retu);
        return NULL;
    }

    uint16_t _x;

    for ( _x = 0; _x < _ext_length; _x++ ) {
        _it += 4;
        bytes_to_U32(&(_retu->table[_x]), _it);
    }

    return _retu;
}

/**
 * @brief Adds header to payload. Make sure _payload_ has enough space.
 *
 * @param header The header.
 * @param payload The payload.
 * @return uint8_t* Iterated position.
 */
uint8_t *add_header ( RTPHeader *header, uint8_t *payload )
{
    uint8_t _cc = GET_FLAG_CSRCC ( header );

    uint8_t *_it = payload;


    /* Add sequence number first */
    U16_to_bytes(_it, header->sequnum);
    _it += 2;

    *_it = header->flags;
    ++_it;
    *_it = header->marker_payloadt;
    ++_it;


    U32_to_bytes( _it, header->timestamp);
    _it += 4;
    U32_to_bytes( _it, header->ssrc);

    uint8_t _x;

    for ( _x = 0; _x < _cc; _x++ ) {
        _it += 4;
        U32_to_bytes( _it, header->csrc[_x]);
    }

    return _it + 4;
}

/**
 * @brief Adds extension header to payload. Make sure _payload_ has enough space.
 *
 * @param header The header.
 * @param payload The payload.
 * @return uint8_t* Iterated position.
 */
uint8_t *add_ext_header ( RTPExtHeader *header, uint8_t *payload )
{
    uint8_t *_it = payload;

    U16_to_bytes(_it, header->length);
    _it += 2;
    U16_to_bytes(_it, header->type);
    _it -= 2; /* Return to 0 position */

    if ( header->table ) {
        uint16_t _x;

        for ( _x = 0; _x < header->length; _x++ ) {
            _it += 4;
            U32_to_bytes(_it, header->table[_x]);
        }
    }

    return _it + 4;
}

/**
 * @brief Builds header from control session values.
 *
 * @param session Control session.
 * @return RTPHeader* Created header.
 */
RTPHeader *build_header ( RTPSession *session )
{
    RTPHeader *_retu = calloc ( 1, sizeof (RTPHeader) );

    if ( !_retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    ADD_FLAG_VERSION ( _retu, session->version );
    ADD_FLAG_PADDING ( _retu, session->padding );
    ADD_FLAG_EXTENSION ( _retu, session->extension );
    ADD_FLAG_CSRCC ( _retu, session->cc );
    ADD_SETTING_MARKER ( _retu, session->marker );
    ADD_SETTING_PAYLOAD ( _retu, session->payload_type );

    _retu->sequnum = session->sequnum;
    _retu->timestamp = current_time_monotonic(); /* milliseconds */
    _retu->ssrc = session->ssrc;

    int i;

    for ( i = 0; i < session->cc; i++ )
        _retu->csrc[i] = session->csrc[i];

    _retu->length = 12 /* Minimum header len */ + ( session->cc * size_32 );

    return _retu;
}


/**
 * @brief Parses data into RTPMessage struct. Stores headers separately from the payload data
 *        and so the length variable is set accordingly. _sequnum_ argument is
 *        passed by the handle_packet() since it's parsed already.
 *
 * @param session Control session.
 * @param sequnum Sequence number that's parsed from payload in handle_packet()
 * @param data Payload data.
 * @param length Payload size.
 * @return RTPMessage*
 * @retval NULL Error occurred.
 */
RTPMessage *msg_parse ( const uint8_t *data, int length )
{
    RTPMessage *_retu = calloc(1, sizeof (RTPMessage));

    _retu->header = extract_header ( data, length ); /* It allocates memory and all */

    if ( !_retu->header ) {
        LOGGER_WARNING("Header failed to extract!");
        free(_retu);
        return NULL;
    }

    uint16_t _from_pos = _retu->header->length;
    _retu->length = length - _from_pos;



    if ( GET_FLAG_EXTENSION ( _retu->header ) ) {
        _retu->ext_header = extract_ext_header ( data + _from_pos, length );

        if ( _retu->ext_header ) {
            _retu->length -= ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );
            _from_pos += ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );
        } else { /* Error */
            LOGGER_WARNING("Ext Header failed to extract!");
            rtp_free_msg(NULL, _retu);
            return NULL;
        }
    } else {
        _retu->ext_header = NULL;
    }

    if ( length - _from_pos <= MAX_RTP_SIZE )
        memcpy ( _retu->data, data + _from_pos, length - _from_pos );
    else {
        LOGGER_WARNING("Invalid length!");
        rtp_free_msg(NULL, _retu);
        return NULL;
    }

    _retu->next = NULL;

    return _retu;
}

/**
 * @brief Callback for networking core.
 *
 * @param object RTPSession object.
 * @param ip_port Where the message comes from.
 * @param data Message data.
 * @param length Message length.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int rtp_handle_packet ( void *object, const uint8_t *data, uint32_t length )
{
    RTPSession *_session = object;
    RTPMessage *_msg;

    if ( !_session || length < 13 ) { /* 12 is the minimum length for rtp + desc. byte */
        LOGGER_WARNING("No session or invalid length of received buffer!");
        return -1;
    }

    _msg = msg_parse ( data + 1, length - 1 );

    if ( !_msg ) {
        LOGGER_WARNING("Could not parse message!");
        return -1;
    }

    /* Check if message came in late */
    if ( check_late_message(_session, _msg) < 0 ) { /* Not late */
        _session->rsequnum = _msg->header->sequnum;
        _session->timestamp = _msg->header->timestamp;
    }

    toxav_handle_packet(_session, _msg);

    return 0;
}



/**
 * @brief Stores headers and payload data in one container ( data )
 *        and the length is set accordingly. Returned message is used for sending _only_.
 *
 * @param session The control session.
 * @param data Payload data to send ( This is what you pass ).
 * @param length Size of the payload data.
 * @return RTPMessage* Created message.
 * @retval NULL Error occurred.
 */
RTPMessage *rtp_new_message ( RTPSession *session, const uint8_t *data, uint32_t length )
{
    if ( !session ) {
        LOGGER_WARNING("No session!");
        return NULL;
    }

    uint8_t *_from_pos;
    RTPMessage *_retu = calloc(1, sizeof (RTPMessage));

    if ( !_retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    /* Sets header values and copies the extension header in _retu */
    _retu->header = build_header ( session ); /* It allocates memory and all */
    _retu->ext_header = session->ext_header;


    uint32_t _total_length = length + _retu->header->length + 1;

    _retu->data[0] = session->prefix;

    if ( _retu->ext_header ) {
        _total_length += ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );

        _from_pos = add_header ( _retu->header, _retu->data + 1 );
        _from_pos = add_ext_header ( _retu->ext_header, _from_pos + 1 );
    } else {
        _from_pos = add_header ( _retu->header, _retu->data + 1 );
    }

    /*
     * Parses the extension header into the message
     * Of course if any
     */

    /* Appends _data on to _retu->_data */
    memcpy ( _from_pos, data, length );

    _retu->length = _total_length;

    _retu->next = NULL;

    return _retu;
}


/**
 * @brief Sends data to _RTPSession::dest
 *
 * @param session The session.
 * @param messenger Tox* object.
 * @param data The payload.
 * @param length Size of the payload.
 * @return int
 * @retval -1 On error.
 * @retval 0 On success.
 */
int rtp_send_msg ( RTPSession *session, Messenger *messenger, const uint8_t *data, uint16_t length )
{
    RTPMessage *msg = rtp_new_message (session, data, length);

    if ( !msg ) {
        LOGGER_WARNING("No session!");
        return -1;
    }

    if ( -1 == send_custom_lossy_packet(messenger, session->dest, msg->data, msg->length) ) {
        LOGGER_WARNING("Failed to send full packet! std error: %s", strerror(errno));
        rtp_free_msg ( session, msg );
        return -1;
    }


    /* Set sequ number */
    session->sequnum = session->sequnum >= MAX_SEQU_NUM ? 0 : session->sequnum + 1;
    rtp_free_msg ( session, msg );

    return 0;
}


/**
 * @brief Speaks for it self.
 *
 * @param session The control session msg belongs to. You set it as NULL when freeing recved messages.
 *                Otherwise set it to session the message was created from.
 * @param msg The message.
 * @return void
 */
void rtp_free_msg ( RTPSession *session, RTPMessage *msg )
{
    if ( !session ) {
        if ( msg->ext_header ) {
            free ( msg->ext_header->table );
            free ( msg->ext_header );
        }
    } else {
        if ( msg->ext_header && session->ext_header != msg->ext_header ) {
            free ( msg->ext_header->table );
            free ( msg->ext_header );
        }
    }

    free ( msg->header );
    free ( msg );
}

/**
 * @brief Must be called before calling any other rtp function. It's used
 *        to initialize RTP control session.
 *
 * @param payload_type Type of payload used to send. You can use values in toxmsi.h::MSICallType
 * @param messenger Tox* object.
 * @param friend_num Friend id.
 * @return RTPSession* Created control session.
 * @retval NULL Error occurred.
 */
RTPSession *rtp_init_session ( int payload_type, Messenger *messenger, int friend_num )
{
    RTPSession *_retu = calloc(1, sizeof(RTPSession));

    if ( !_retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    if ( -1 == custom_lossy_packet_registerhandler(messenger, friend_num, payload_type, rtp_handle_packet, _retu)) {
        LOGGER_ERROR("Error setting custom register handler for rtp session");
        free(_retu);
        return NULL;
    }

    LOGGER_DEBUG("Registered packet handler: pt: %d; fid: %d", payload_type, friend_num);

    _retu->version   = RTP_VERSION;   /* It's always 2 */
    _retu->padding   = 0;             /* If some additional data is needed about the packet */
    _retu->extension = 0;           /* If extension to header is needed */
    _retu->cc        = 1;           /* Amount of contributors */
    _retu->csrc      = NULL;        /* Container */
    _retu->ssrc      = random_int();
    _retu->marker    = 0;
    _retu->payload_type = payload_type % 128;

    _retu->dest = friend_num;

    _retu->rsequnum = _retu->sequnum = 0;

    _retu->ext_header = NULL; /* When needed allocate */


    if ( !(_retu->csrc = calloc(1, sizeof (uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(_retu);
        return NULL;
    }

    _retu->csrc[0] = _retu->ssrc; /* Set my ssrc to the list receive */

    /* Also set payload type as prefix */
    _retu->prefix = payload_type;

    /*
     *
     */
    return _retu;
}


/**
 * @brief Terminate the session.
 *
 * @param session The session.
 * @param messenger The messenger who owns the session
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
void rtp_terminate_session ( RTPSession *session, Messenger *messenger )
{
    if ( !session ) return;

    custom_lossy_packet_registerhandler(messenger, session->dest, session->prefix, NULL, NULL);

    free ( session->ext_header );
    free ( session->csrc );

    LOGGER_DEBUG("Terminated RTP session: %p", session);

    /* And finally free session */
    free ( session );

}
