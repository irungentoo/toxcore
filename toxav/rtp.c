/**  toxrtp.c
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
 *
 *   Report bugs/suggestions at #tox-dev @ freenode.net:6667
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "rtp.h"
#include <assert.h>
#include <stdlib.h>


#define PAYLOAD_ID_VALUE_OPUS 1
#define PAYLOAD_ID_VALUE_VP8  2

#define size_32 4

#define inline__ inline __attribute__((always_inline))


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
 * @brief Converts 4 bytes to uint32_t
 *
 * @param dest Where to convert
 * @param bytes What bytes
 * @return void
 */
inline__ void bytes_to_U32(uint32_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint32_t ) *  bytes )              |
        ( ( uint32_t ) * ( bytes + 1 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 2 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 3 ) << 24 ) ;
#else
        ( ( uint32_t ) *  bytes        << 24 ) |
        ( ( uint32_t ) * ( bytes + 1 ) << 16 ) |
        ( ( uint32_t ) * ( bytes + 2 ) << 8 )  |
        ( ( uint32_t ) * ( bytes + 3 ) ) ;
#endif
}

/**
 * @brief Converts 2 bytes to uint16_t
 *
 * @param dest Where to convert
 * @param bytes What bytes
 * @return void
 */
inline__ void bytes_to_U16(uint16_t *dest, const uint8_t *bytes)
{
    *dest =
#ifdef WORDS_BIGENDIAN
        ( ( uint16_t ) *   bytes ) |
        ( ( uint16_t ) * ( bytes + 1 ) << 8 );
#else
        ( ( uint16_t ) *   bytes << 8 ) |
        ( ( uint16_t ) * ( bytes + 1 ) );
#endif
}

/**
 * @brief Convert uint32_t to byte string of size 4
 *
 * @param dest Where to convert
 * @param value The value
 * @return void
 */
inline__ void U32_to_bytes(uint8_t *dest, uint32_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
    *(dest + 2) = ( value >> 16 );
    *(dest + 3) = ( value >> 24 );
#else
    *(dest)     = ( value >> 24 );
    *(dest + 1) = ( value >> 16 );
    *(dest + 2) = ( value >> 8 );
    *(dest + 3) = ( value );
#endif
}

/**
 * @brief Convert uint16_t to byte string of size 2
 *
 * @param dest Where to convert
 * @param value The value
 * @return void
 */
inline__ void U16_to_bytes(uint8_t *dest, uint16_t value)
{
#ifdef WORDS_BIGENDIAN
    *(dest)     = ( value );
    *(dest + 1) = ( value >> 8 );
#else
    *(dest)     = ( value >> 8 );
    *(dest + 1) = ( value );
#endif
}


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
 * @brief Increases nonce value by 'target'
 *
 * @param nonce The nonce
 * @param target The target
 * @return void
 */
inline__ void increase_nonce(uint8_t *nonce, uint16_t target)
{
    uint16_t _nonce_counter;

    uint8_t _reverse_bytes[2];
    _reverse_bytes[0] = nonce[crypto_secretbox_NONCEBYTES - 1];
    _reverse_bytes[1] = nonce[crypto_secretbox_NONCEBYTES - 2];

    bytes_to_U16(&_nonce_counter, _reverse_bytes );

    /* Check overflow */
    if (_nonce_counter > UINT16_MAX - target ) { /* 2 bytes are not long enough */
        uint8_t _it = 3;

        while ( _it <= crypto_secretbox_NONCEBYTES ) _it += ++nonce[crypto_secretbox_NONCEBYTES - _it] ?
                    crypto_secretbox_NONCEBYTES : 1;

        _nonce_counter = _nonce_counter - (UINT16_MAX - target ); /* Assign the rest of it */
    } else { /* Increase nonce */

        _nonce_counter += target;
    }

    /* Assign the last bytes */

    U16_to_bytes( _reverse_bytes, _nonce_counter);
    nonce [crypto_secretbox_NONCEBYTES - 1] = _reverse_bytes[0];
    nonce [crypto_secretbox_NONCEBYTES - 2] = _reverse_bytes[1];

}


/**
 * @brief Speaks for it self.
 *
 */
static const uint32_t payload_table[] = {
    8000, 8000, 8000, 8000, 8000, 8000, 16000, 8000, 8000, 8000,        /*    0-9    */
    44100, 44100, 0, 0, 90000, 8000, 11025, 22050, 0, 0,                /*   10-19   */
    0, 0, 0, 0, 0, 90000, 90000, 0, 90000, 0,                           /*   20-29   */
    0, 90000, 90000, 90000, 90000, 0, 0, 0, 0, 0,                       /*   30-39   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*   40-49   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*   50-59   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*   60-69   */
    PAYLOAD_ID_VALUE_OPUS, PAYLOAD_ID_VALUE_VP8, 0, 0, 0, 0, 0, 0, 0, 0,/*   70-79   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*   80-89   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*   90-99   */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*  100-109  */
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,                                       /*  110-119  */
    0, 0, 0, 0, 0, 0, 0, 0                                              /*  120-127  */
};


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
        return NULL;
    }

    const uint8_t *_it = payload;

    RTPHeader *_retu = calloc(1, sizeof (RTPHeader));
    assert(_retu);

    _retu->flags = *_it;
    ++_it;

    /* This indicates if the first 2 bits are valid.
     * Now it may happen that this is out of order but
     * it cuts down chances of parsing some invalid value
     */

    if ( GET_FLAG_VERSION(_retu) != RTP_VERSION ) {
        /* Deallocate */
        free(_retu);
        return NULL;
    }

    /*
     * Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t _cc = GET_FLAG_CSRCC ( _retu );
    uint32_t _length = 12 /* Minimum header len */ + ( _cc * 4 );

    if ( length < _length ) {
        /* Deallocate */
        free(_retu);
        return NULL;
    }

    if ( _cc > 0 ) {
        _retu->csrc = calloc (_cc, sizeof (uint32_t));
        assert(_retu->csrc);

    } else { /* But this should not happen ever */
        /* Deallocate */
        free(_retu);
        return NULL;
    }


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
    assert(_retu);

    uint16_t _ext_length;
    bytes_to_U16(&_ext_length, _it);
    _it += 2;


    if ( length < ( _ext_length * sizeof(uint32_t) ) ) {
        free(_retu);
        return NULL;
    }

    _retu->length  = _ext_length;
    bytes_to_U16(&_retu->type, _it);
    _it += 2;

    _retu->table = calloc(_ext_length, sizeof (uint32_t));
    assert(_retu->table);

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

    if ( header->csrc ) {
        uint8_t _x;

        for ( _x = 0; _x < _cc; _x++ ) {
            _it += 4;
            U32_to_bytes( _it, header->csrc[_x]);
        }
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
    assert(_retu);

    ADD_FLAG_VERSION ( _retu, session->version );
    ADD_FLAG_PADDING ( _retu, session->padding );
    ADD_FLAG_EXTENSION ( _retu, session->extension );
    ADD_FLAG_CSRCC ( _retu, session->cc );
    ADD_SETTING_MARKER ( _retu, session->marker );
    ADD_SETTING_PAYLOAD ( _retu, session->payload_type );

    _retu->sequnum = session->sequnum;
    _retu->timestamp = ((uint32_t)(current_time() / 1000)); /* micro to milli */
    _retu->ssrc = session->ssrc;

    if ( session->cc > 0 ) {
        _retu->csrc = calloc(session->cc, sizeof (uint32_t));
        assert(_retu->csrc);

        int i;

        for ( i = 0; i < session->cc; i++ ) {
            _retu->csrc[i] = session->csrc[i];
        }
    } else {
        _retu->csrc = NULL;
    }

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
RTPMessage *msg_parse ( uint16_t sequnum, const uint8_t *data, int length )
{
    RTPMessage *_retu = calloc(1, sizeof (RTPMessage));

    _retu->header = extract_header ( data, length ); /* It allocates memory and all */

    if ( !_retu->header ) {
        free(_retu);
        return NULL;
    }

    _retu->header->sequnum = sequnum;

    _retu->length = length - _retu->header->length;

    uint16_t _from_pos = _retu->header->length - 2 /* Since sequ num is excluded */ ;


    if ( GET_FLAG_EXTENSION ( _retu->header ) ) {
        _retu->ext_header = extract_ext_header ( data + _from_pos, length );

        if ( _retu->ext_header ) {
            _retu->length -= ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );
            _from_pos += ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );
        } else { /* Error */
            free (_retu->ext_header);
            free (_retu->header);
            free (_retu);
            return NULL;
        }
    } else {
        _retu->ext_header = NULL;
    }

    if ( length - _from_pos <= MAX_RTP_SIZE )
        memcpy ( _retu->data, data + _from_pos, length - _from_pos );
    else {
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
int rtp_handle_packet ( void *object, IP_Port ip_port, uint8_t *data, uint32_t length )
{
    RTPSession *_session = object;
    RTPMessage *_msg;

    if ( !_session || length < 13 + crypto_secretbox_MACBYTES) /* 12 is the minimum length for rtp + desc. byte */
        return -1;

    uint8_t _plain[MAX_UDP_PACKET_SIZE];

    uint16_t _sequnum;
    bytes_to_U16(&_sequnum, data + 1);

    /* Clculate the right nonce */
    uint8_t _calculated[crypto_secretbox_NONCEBYTES];
    memcpy(_calculated, _session->decrypt_nonce, crypto_secretbox_NONCEBYTES);
    increase_nonce ( _calculated, _sequnum );

    /* Decrypt message */
    int _decrypted_length = decrypt_data_symmetric(
                                (uint8_t *)_session->decrypt_key, _calculated, data + 3, length - 3, _plain );

    /* This packet is either not encrypted properly or late
     */
    if ( -1 == _decrypted_length ) {

        /* If this is the case, then the packet is most likely late.
         * Try with old nonce cycle.
         */
        if ( _session->rsequnum < _sequnum ) {
            _decrypted_length = decrypt_data_symmetric(
                                    (uint8_t *)_session->decrypt_key, _session->nonce_cycle, data + 3, length - 3, _plain );

            if ( !_decrypted_length ) return -1; /* This packet is not encrypted properly */

            /* Otherwise, if decryption is ok with new cycle, set new cycle
             */
        } else {
            increase_nonce ( _calculated, MAX_SEQU_NUM );
            _decrypted_length = decrypt_data_symmetric(
                                    (uint8_t *)_session->decrypt_key, _calculated, data + 3, length - 3, _plain );

            if ( !_decrypted_length ) return -1; /* This is just an error */

            /* A new cycle setting. */
            memcpy(_session->nonce_cycle, _session->decrypt_nonce, crypto_secretbox_NONCEBYTES);
            memcpy(_session->decrypt_nonce, _calculated, crypto_secretbox_NONCEBYTES);
        }
    }

    _msg = msg_parse ( _sequnum, _plain, _decrypted_length );

    if ( !_msg ) return -1;

    /* Hopefully this goes well
     * NOTE: Is this even used?
     */
    memcpy(&_msg->from, &ip_port, sizeof(IP_Port));

    /* Check if message came in late */
    if ( check_late_message(_session, _msg) < 0 ) { /* Not late */
        _session->rsequnum = _msg->header->sequnum;
        _session->timestamp = _msg->header->timestamp;
    }

    pthread_mutex_lock(&_session->mutex);

    if ( _session->last_msg ) {
        _session->last_msg->next = _msg;
        _session->last_msg = _msg;
    } else {
        _session->last_msg = _session->oldest_msg = _msg;
    }

    pthread_mutex_unlock(&_session->mutex);

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
    if ( !session )
        return NULL;

    uint8_t *_from_pos;
    RTPMessage *_retu = calloc(1, sizeof (RTPMessage));
    assert(_retu);

    /* Sets header values and copies the extension header in _retu */
    _retu->header = build_header ( session ); /* It allocates memory and all */
    _retu->ext_header = session->ext_header;


    uint32_t _total_length = length + _retu->header->length;

    if ( _retu->ext_header ) {
        _total_length += ( 4 /* Minimum ext header len */ + _retu->ext_header->length * size_32 );

        _from_pos = add_header ( _retu->header, _retu->data );
        _from_pos = add_ext_header ( _retu->ext_header, _from_pos + 1 );
    } else {
        _from_pos = add_header ( _retu->header, _retu->data );
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







/********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 *
 *
 *
 * PUBLIC API FUNCTIONS IMPLEMENTATIONS
 *
 *
 *
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************/









/**
 * @brief Release all messages held by session.
 *
 * @param session The session.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int rtp_release_session_recv ( RTPSession *session )
{
    if ( !session ) {
        return -1;
    }

    RTPMessage *_tmp, * _it;

    pthread_mutex_lock(&session->mutex);

    for ( _it = session->oldest_msg; _it; _it = _tmp ) {
        _tmp = _it->next;
        rtp_free_msg( session, _it);
    }

    session->last_msg = session->oldest_msg = NULL;

    pthread_mutex_unlock(&session->mutex);

    return 0;
}


/**
 * @brief Gets oldest message in the list.
 *
 * @param session Where the list is.
 * @return RTPMessage* The message. You _must_ call rtp_msg_free() to free it.
 * @retval NULL No messages in the list, or no list.
 */
RTPMessage *rtp_recv_msg ( RTPSession *session )
{
    if ( !session )
        return NULL;

    RTPMessage *_retu = session->oldest_msg;

    pthread_mutex_lock(&session->mutex);

    if ( _retu )
        session->oldest_msg = _retu->next;

    if ( !session->oldest_msg )
        session->last_msg = NULL;

    pthread_mutex_unlock(&session->mutex);

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

    if ( !msg ) return -1;

    uint8_t _send_data [ MAX_UDP_PACKET_SIZE ];

    _send_data[0] = session->prefix;

    /* Generate the right nonce */
    uint8_t _calculated[crypto_secretbox_NONCEBYTES];
    memcpy(_calculated, session->encrypt_nonce, crypto_secretbox_NONCEBYTES);
    increase_nonce ( _calculated, msg->header->sequnum );

    /* Need to skip 2 bytes that are for sequnum */
    int encrypted_length = encrypt_data_symmetric( /* TODO: msg->length - 2 (fix this properly)*/
                               (uint8_t *) session->encrypt_key, _calculated, msg->data + 2, msg->length, _send_data + 3 );

    int full_length = encrypted_length + 3;

    _send_data[1] = msg->data[0];
    _send_data[2] = msg->data[1];


    /*if ( full_length != sendpacket ( messenger->net, *((IP_Port*) &session->dest), _send_data, full_length) ) {*/
    if ( full_length != send_custom_user_packet(messenger, session->dest, _send_data, full_length) ) {
        printf("Rtp error: %s\n", strerror(errno));
        return -1;
    }


    /* Set sequ number */
    if ( session->sequnum >= MAX_SEQU_NUM ) {
        session->sequnum = 0;
        memcpy(session->encrypt_nonce, _calculated, crypto_secretbox_NONCEBYTES);
    } else {
        session->sequnum++;
    }

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
        free ( msg->header->csrc );

        if ( msg->ext_header ) {
            free ( msg->ext_header->table );
            free ( msg->ext_header );
        }
    } else {
        if ( session->csrc != msg->header->csrc )
            free ( msg->header->csrc );

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
 * @param encrypt_key Speaks for it self.
 * @param decrypt_key Speaks for it self.
 * @param encrypt_nonce Speaks for it self.
 * @param decrypt_nonce Speaks for it self.
 * @return RTPSession* Created control session.
 * @retval NULL Error occurred.
 */
RTPSession *rtp_init_session ( int            payload_type,
                               Messenger     *messenger,
                               int            friend_num,
                               const uint8_t *encrypt_key,
                               const uint8_t *decrypt_key,
                               const uint8_t *encrypt_nonce,
                               const uint8_t *decrypt_nonce )
{
    RTPSession *_retu = calloc(1, sizeof(RTPSession));
    assert(_retu);

    /*networking_registerhandler(messenger->net, payload_type, rtp_handle_packet, _retu);*/
    if ( -1 == custom_user_packet_registerhandler(messenger, friend_num, payload_type, rtp_handle_packet, _retu) ) {
        fprintf(stderr, "Error setting custom register handler for rtp session\n");
        free(_retu);
        return NULL;
    }

    _retu->version   = RTP_VERSION;   /* It's always 2 */
    _retu->padding   = 0;             /* If some additional data is needed about the packet */
    _retu->extension = 0;           /* If extension to header is needed */
    _retu->cc        = 1;           /* Amount of contributors */
    _retu->csrc      = NULL;        /* Container */
    _retu->ssrc      = random_int();
    _retu->marker    = 0;
    _retu->payload_type = payload_table[payload_type];

    _retu->dest = friend_num;

    _retu->rsequnum = _retu->sequnum = 1;

    _retu->ext_header = NULL; /* When needed allocate */
    _retu->framerate = -1;
    _retu->resolution = -1;

    _retu->encrypt_key = encrypt_key;
    _retu->decrypt_key = decrypt_key;

    /* Need to allocate new memory */
    _retu->encrypt_nonce = calloc ( crypto_secretbox_NONCEBYTES, sizeof (uint8_t) );
    assert(_retu->encrypt_nonce);
    _retu->decrypt_nonce = calloc ( crypto_secretbox_NONCEBYTES, sizeof (uint8_t) );
    assert(_retu->decrypt_nonce);
    _retu->nonce_cycle   = calloc ( crypto_secretbox_NONCEBYTES, sizeof (uint8_t) );
    assert(_retu->nonce_cycle);

    memcpy(_retu->encrypt_nonce, encrypt_nonce, crypto_secretbox_NONCEBYTES);
    memcpy(_retu->decrypt_nonce, decrypt_nonce, crypto_secretbox_NONCEBYTES);
    memcpy(_retu->nonce_cycle  , decrypt_nonce, crypto_secretbox_NONCEBYTES);

    _retu->csrc = calloc(1, sizeof (uint32_t));
    assert(_retu->csrc);

    _retu->csrc[0] = _retu->ssrc; /* Set my ssrc to the list receive */

    /* Also set payload type as prefix */
    _retu->prefix = payload_type;

    _retu->oldest_msg = _retu->last_msg = NULL;

    pthread_mutex_init(&_retu->mutex, NULL);
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
int rtp_terminate_session ( RTPSession *session, Messenger *messenger )
{
    if ( !session )
        return -1;

    custom_user_packet_registerhandler(messenger, session->dest, session->prefix, NULL, NULL);

    free ( session->ext_header );
    free ( session->csrc );
    free ( session->decrypt_nonce );
    free ( session->encrypt_nonce );
    free ( session->nonce_cycle );

    pthread_mutex_destroy(&session->mutex);

    /* And finally free session */
    free ( session );

    return 0;
}