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
void queue_message(RTPSession *_session, RTPMessage *_msg);

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
 * Checks if message came in late.
 */
static int check_late_message (RTPSession *session, RTPMessage *msg)
{
    /*
     * Check Sequence number. If this new msg has lesser number then the session->rsequnum
     * it shows that the message came in late. Also check timestamp to be 100% certain.
     *
     */
    return ( msg->header->sequnum < session->rsequnum && msg->header->timestamp < session->timestamp ) ? 0 : -1;
}


/**
 * Extracts header from payload.
 */
RTPHeader *extract_header ( const uint8_t *payload, int length )
{
    if ( !payload || !length ) {
        LOGGER_WARNING("No payload to extract!");
        return NULL;
    }

    RTPHeader *retu = calloc(1, sizeof (RTPHeader));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    memcpy(&retu->sequnum, payload, sizeof(retu->sequnum));
    retu->sequnum = ntohs(retu->sequnum);

    const uint8_t *it = payload + 2;

    retu->flags = *it;
    ++it;

    /* This indicates if the first 2 bits are valid.
     * Now it may happen that this is out of order but
     * it cuts down chances of parsing some invalid value
     */

    if ( GET_FLAG_VERSION(retu) != RTP_VERSION ) {
        /* Deallocate */
        LOGGER_WARNING("Invalid version!");
        free(retu);
        return NULL;
    }

    /*
     * Added a check for the size of the header little sooner so
     * I don't need to parse the other stuff if it's bad
     */
    uint8_t cc = GET_FLAG_CSRCC ( retu );
    int total = 12 /* Minimum header len */ + ( cc * 4 );

    if ( length < total ) {
        /* Deallocate */
        LOGGER_WARNING("Length invalid!");
        free(retu);
        return NULL;
    }

    memset(retu->csrc, 0, 16 * sizeof (uint32_t));

    retu->marker_payloadt = *it;
    ++it;
    retu->length = total;


    memcpy(&retu->timestamp, it, sizeof(retu->timestamp));
    retu->timestamp = ntohl(retu->timestamp);
    it += 4;
    memcpy(&retu->ssrc, it, sizeof(retu->ssrc));
    retu->ssrc = ntohl(retu->ssrc);

    uint8_t x;

    for ( x = 0; x < cc; x++ ) {
        it += 4;
        memcpy(&retu->csrc[x], it, sizeof(retu->csrc[x]));
        retu->csrc[x] = ntohl(retu->csrc[x]);
    }

    return retu;
}

/**
 * Extracts external header from payload. Must be called AFTER extract_header()!
 */
RTPExtHeader *extract_ext_header ( const uint8_t *payload, uint16_t length )
{
    const uint8_t *it = payload;

    RTPExtHeader *retu = calloc(1, sizeof (RTPExtHeader));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    uint16_t ext_length;
    memcpy(&ext_length, it, sizeof(ext_length));
    ext_length = ntohs(ext_length);
    it += 2;


    if ( length < ( ext_length * sizeof(uint32_t) ) ) {
        LOGGER_WARNING("Length invalid!");
        free(retu);
        return NULL;
    }

    retu->length  = ext_length;
    memcpy(&retu->type, it, sizeof(retu->type));
    retu->type = ntohs(retu->type);
    it += 2;

    if ( !(retu->table = calloc(ext_length, sizeof (uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(retu);
        return NULL;
    }

    uint16_t x;

    for ( x = 0; x < ext_length; x++ ) {
        it += 4;
        memcpy(&(retu->table[x]), it, sizeof(retu->table[x]));
        retu->table[x] = ntohl(retu->table[x]);
    }

    return retu;
}

/**
 * Adds header to payload. Make sure _payload_ has enough space.
 */
uint8_t *add_header ( RTPHeader *header, uint8_t *payload )
{
    uint8_t cc = GET_FLAG_CSRCC ( header );
    uint8_t *it = payload;
    uint16_t sequnum;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc;


    /* Add sequence number first */
    sequnum = htons(header->sequnum);
    memcpy(it, &sequnum, sizeof(sequnum));
    it += 2;

    *it = header->flags;
    ++it;
    *it = header->marker_payloadt;
    ++it;


    timestamp = htonl(header->timestamp);
    memcpy(it, &timestamp, sizeof(timestamp));
    it += 4;
    ssrc = htonl(header->ssrc);
    memcpy(it, &ssrc, sizeof(ssrc));

    uint8_t x;

    for ( x = 0; x < cc; x++ ) {
        it += 4;
        csrc = htonl(header->csrc[x]);
        memcpy(it, &csrc, sizeof(csrc));
    }

    return it + 4;
}

/**
 * Adds extension header to payload. Make sure _payload_ has enough space.
 */
uint8_t *add_ext_header ( RTPExtHeader *header, uint8_t *payload )
{
    uint8_t *it = payload;
    uint16_t length;
    uint16_t type;
    uint32_t entry;

    length = htons(header->length);
    memcpy(it, &length, sizeof(length));
    it += 2;
    type = htons(header->type);
    memcpy(it, &type, sizeof(type));
    it -= 2; /* Return to 0 position */

    if ( header->table ) {

        uint16_t x;

        for ( x = 0; x < header->length; x++ ) {
            it += 4;
            entry = htonl(header->table[x]);
            memcpy(it, &entry, sizeof(entry));
        }
    }

    return it + 4;
}

/**
 * Builds header from control session values.
 */
RTPHeader *build_header ( RTPSession *session )
{
    RTPHeader *retu = calloc ( 1, sizeof (RTPHeader) );

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    ADD_FLAG_VERSION ( retu, session->version );
    ADD_FLAG_PADDING ( retu, session->padding );
    ADD_FLAG_EXTENSION ( retu, session->extension );
    ADD_FLAG_CSRCC ( retu, session->cc );
    ADD_SETTING_MARKER ( retu, session->marker );
    ADD_SETTING_PAYLOAD ( retu, session->payload_type );

    retu->sequnum = session->sequnum;
    retu->timestamp = current_time_monotonic(); /* milliseconds */
    retu->ssrc = session->ssrc;

    int i;

    for ( i = 0; i < session->cc; i++ )
        retu->csrc[i] = session->csrc[i];

    retu->length = 12 /* Minimum header len */ + ( session->cc * size_32 );

    return retu;
}


/**
 * Parses data into RTPMessage struct. Stores headers separately from the payload data
 * and so the length variable is set accordingly.
 */
RTPMessage *msg_parse ( const uint8_t *data, int length )
{
    RTPMessage *retu = calloc(1, sizeof (RTPMessage));

    retu->header = extract_header ( data, length ); /* It allocates memory and all */

    if ( !retu->header ) {
        LOGGER_WARNING("Header failed to extract!");
        free(retu);
        return NULL;
    }

    uint16_t from_pos = retu->header->length;
    retu->length = length - from_pos;



    if ( GET_FLAG_EXTENSION ( retu->header ) ) {
        retu->ext_header = extract_ext_header ( data + from_pos, length );

        if ( retu->ext_header ) {
            retu->length -= ( 4 /* Minimum ext header len */ + retu->ext_header->length * size_32 );
            from_pos += ( 4 /* Minimum ext header len */ + retu->ext_header->length * size_32 );
        } else { /* Error */
            LOGGER_WARNING("Ext Header failed to extract!");
            rtp_free_msg(NULL, retu);
            return NULL;
        }
    } else {
        retu->ext_header = NULL;
    }

    if ( length - from_pos <= MAX_RTP_SIZE )
        memcpy ( retu->data, data + from_pos, length - from_pos );
    else {
        LOGGER_WARNING("Invalid length!");
        rtp_free_msg(NULL, retu);
        return NULL;
    }

    retu->next = NULL;

    return retu;
}

/**
 * Callback for networking core.
 */
int rtp_handle_packet ( Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object )
{
    RTPSession *session = object;
    RTPMessage *msg;

    if ( !session || length < 13 ) { /* 12 is the minimum length for rtp + desc. byte */
        LOGGER_WARNING("No session or invalid length of received buffer!");
        return -1;
    }

    msg = msg_parse ( data + 1, length - 1 );

    if ( !msg ) {
        LOGGER_WARNING("Could not parse message!");
        return -1;
    }

    /* Check if message came in late */
    if ( check_late_message(session, msg) < 0 ) { /* Not late */
        session->rsequnum = msg->header->sequnum;
        session->timestamp = msg->header->timestamp;
    }

    queue_message(session, msg);

    return 0;
}

/**
 * Allocate message and store data there
 */
RTPMessage *rtp_new_message ( RTPSession *session, const uint8_t *data, uint32_t length )
{
    if ( !session ) {
        LOGGER_WARNING("No session!");
        return NULL;
    }

    uint8_t *from_pos;
    RTPMessage *retu = calloc(1, sizeof (RTPMessage));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    /* Sets header values and copies the extension header in retu */
    retu->header = build_header ( session ); /* It allocates memory and all */
    retu->ext_header = session->ext_header;


    uint32_t total_length = length + retu->header->length + 1;

    retu->data[0] = session->prefix;

    if ( retu->ext_header ) {
        total_length += ( 4 /* Minimum ext header len */ + retu->ext_header->length * size_32 );

        from_pos = add_header ( retu->header, retu->data + 1 );
        from_pos = add_ext_header ( retu->ext_header, from_pos + 1 );
    } else {
        from_pos = add_header ( retu->header, retu->data + 1 );
    }

    /*
     * Parses the extension header into the message
     * Of course if any
     */

    /* Appends data on to retu->data */
    memcpy ( from_pos, data, length );

    retu->length = total_length;

    retu->next = NULL;

    return retu;
}



int rtp_send_msg ( RTPSession *session, Messenger *messenger, const uint8_t *data, uint16_t length )
{
    RTPMessage *msg = rtp_new_message (session, data, length);

    if ( !msg ) return -1;

    int ret = send_custom_lossy_packet(messenger, session->dest, msg->data, msg->length);

    if ( 0 !=  ret) {
        LOGGER_WARNING("Failed to send full packet (len: %d)! error: %i", length, ret);
        rtp_free_msg ( session, msg );
        return rtp_ErrorSending;
    }

    /* Set sequ number */
    session->sequnum = session->sequnum >= MAX_SEQU_NUM ? 0 : session->sequnum + 1;
    rtp_free_msg ( session, msg );

    return 0;
}

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

RTPSession *rtp_new ( int payload_type, Messenger *messenger, int friend_num )
{
    RTPSession *retu = calloc(1, sizeof(RTPSession));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    if ( -1 == m_callback_rtp_packet(messenger, friend_num, payload_type, rtp_handle_packet, retu)) {
        LOGGER_ERROR("Error setting custom register handler for rtp session");
        free(retu);
        return NULL;
    }

    LOGGER_DEBUG("Registered packet handler: pt: %d; fid: %d", payload_type, friend_num);

    retu->version   = RTP_VERSION;   /* It's always 2 */
    retu->padding   = 0;             /* If some additional data is needed about the packet */
    retu->extension = 0;           /* If extension to header is needed */
    retu->cc        = 1;           /* Amount of contributors */
    retu->csrc      = NULL;        /* Container */
    retu->ssrc      = random_int();
    retu->marker    = 0;
    retu->payload_type = payload_type % 128;

    retu->dest = friend_num;

    retu->rsequnum = retu->sequnum = 0;

    retu->ext_header = NULL; /* When needed allocate */


    if ( !(retu->csrc = calloc(1, sizeof (uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(retu);
        return NULL;
    }

    retu->csrc[0] = retu->ssrc; /* Set my ssrc to the list receive */

    /* Also set payload type as prefix */
    retu->prefix = payload_type;

    /*
     *
     */
    return retu;
}

void rtp_kill ( RTPSession *session, Messenger *messenger )
{
    if ( !session ) return;

    m_callback_rtp_packet(messenger, session->dest, session->prefix, NULL, NULL);

    free ( session->ext_header );
    free ( session->csrc );

    LOGGER_DEBUG("Terminated RTP session: %p", session);

    /* And finally free session */
    free ( session );

}
