/**  rtp.c
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
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
#include "../toxcore/Messenger.h"

#include "rtp.h"
#include <stdlib.h>
#include <assert.h>

#define size_32 4
#define RTCP_REPORT_INTERVAL_MS 500

#define ADD_FLAG_VERSION(_h, _v) do { ( _h->flags ) &= 0x3F; ( _h->flags ) |= ( ( ( _v ) << 6 ) & 0xC0 ); } while(0)
#define ADD_FLAG_PADDING(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->flags ) &= 0xDF; ( _h->flags ) |= ( ( ( _v ) << 5 ) & 0x20 ); } while(0)
#define ADD_FLAG_EXTENSION(_h, _v) do { if ( _v > 0 ) _v = 1; ( _h->flags ) &= 0xEF;( _h->flags ) |= ( ( ( _v ) << 4 ) & 0x10 ); } while(0)
#define ADD_FLAG_CSRCC(_h, _v) do { ( _h->flags ) &= 0xF0; ( _h->flags ) |= ( ( _v ) & 0x0F ); } while(0)
#define ADD_SETTING_MARKER(_h, _v) do { ( _h->marker_payloadt ) &= 0x7F; ( _h->marker_payloadt ) |= ( ( ( _v ) << 7 ) /*& 0x80 */ ); } while(0)
#define ADD_SETTING_PAYLOAD(_h, _v) do { ( _h->marker_payloadt ) &= 0x80; ( _h->marker_payloadt ) |= ( ( _v ) /* & 0x7F */ ); } while(0)

#define GET_FLAG_VERSION(_h) (( _h->flags & 0xd0 ) >> 6)
#define GET_FLAG_PADDING(_h) (( _h->flags & 0x20 ) >> 5)
#define GET_FLAG_EXTENSION(_h) (( _h->flags & 0x10 ) >> 4)
#define GET_FLAG_CSRCC(_h) ( _h->flags & 0x0f )
#define GET_SETTING_MARKER(_h) (( _h->marker_payloadt ) >> 7)
#define GET_SETTING_PAYLOAD(_h) ((_h->marker_payloadt) & 0x7f)


typedef struct {
    uint64_t timestamp; /* in ms */
    
    uint32_t received_packets;
    uint32_t expected_packets;
    /* ... other stuff in the future */
} RTCPReport;

typedef struct RTCPSession_s {
    RTPSession *rtp_session;
    
    uint8_t prefix;
    uint64_t last_sent_report_ts;
    uint32_t last_received_packets;
    uint32_t last_expected_packets;
    
    RingBuffer* pl_stats; /* Packet loss stats over time */
} RTCPSession;


RTPHeader *parse_header_in ( const uint8_t *payload, int length );
RTPExtHeader *parse_ext_header_in ( const uint8_t *payload, uint16_t length );
uint8_t *parse_header_out ( const RTPHeader* header, uint8_t* payload );
uint8_t *parse_ext_header_out ( const RTPExtHeader* header, uint8_t* payload );
int handle_rtp_packet ( Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object );
int handle_rtcp_packet ( Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object );
void send_rtcp_report ( RTCPSession* session, Messenger* m, uint32_t friendnumber );


RTPSession *rtp_new ( int payload_type, Messenger *m, int friend_num, void* cs, int (*mcb) (void*, RTPMessage*) )
{
    assert(mcb);
    assert(cs);
    assert(m);
    
    RTPSession *retu = calloc(1, sizeof(RTPSession));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    retu->version   = RTP_VERSION; /* It's always 2 */
    retu->ssrc      = random_int();
    retu->payload_type = payload_type % 128;
    
    retu->m = m;
    retu->friend_number = friend_num;

    if ( !(retu->csrc = calloc(1, sizeof(uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(retu);
        return NULL;
    }
    
    retu->csrc[0] = retu->ssrc; /* Set my ssrc to the list receive */

    /* Also set payload type as prefix */
    retu->prefix = payload_type;
    
    retu->cs = cs;
    retu->mcb = mcb;
    
    /* Initialize rtcp session */
    if (!(retu->rtcp_session = calloc(1, sizeof(RTCPSession)))) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(retu->csrc);
        free(retu);
        return NULL;
    }
    
    retu->rtcp_session->prefix = payload_type + 2;
    retu->rtcp_session->pl_stats = rb_new(4);
    retu->rtcp_session->rtp_session = retu;
    
    if (-1 == rtp_start_receiving(retu)) {
        LOGGER_WARNING("Failed to start rtp receiving mode");
        free(retu->rtcp_session);
        free(retu->csrc);
        free(retu);
        return NULL;
    }
    
    return retu;
}
void rtp_kill ( RTPSession *session )
{
    if ( !session ) return;

	rtp_stop_receiving (session);

    free ( session->ext_header );
    free ( session->csrc );
    
    void* t;
    while (!rb_empty(session->rtcp_session->pl_stats)) {
        rb_read(session->rtcp_session->pl_stats, (void**) &t);
        free(t);
    }
    rb_free(session->rtcp_session->pl_stats);
    
    LOGGER_DEBUG("Terminated RTP session: %p", session);

    /* And finally free session */
    free ( session );
}
int rtp_do(RTPSession *session)
{
    if (!session || !session->rtcp_session)
        return rtp_StateNormal;
    
    if (current_time_monotonic() - session->rtcp_session->last_sent_report_ts >= RTCP_REPORT_INTERVAL_MS) {
        send_rtcp_report(session->rtcp_session, session->m, session->friend_number);
    }
    
    if (rb_full(session->rtcp_session->pl_stats)) {
        RTCPReport* reports[4];
        
        int i = 0;
        for (; i < 4; i++)
            rb_read(session->rtcp_session->pl_stats, (void**) reports + i);
        
        /* Check for timed out reports (> 6 sec) */
        uint64_t now = current_time_monotonic();
        for (i = 0; i < 4 && (now - reports[i]->timestamp) < 6000; i ++);
        for (; i < 4; i ++) {
            rb_write(session->rtcp_session->pl_stats, reports[i]);
            reports[i] = NULL;
        }
        if (!rb_empty(session->rtcp_session->pl_stats)) {
            for (i = 0; reports[i] != NULL; i ++)
                free(reports[i]);
            return rtp_StateNormal; /* As some reports are timed out, we need more */
        }
        
        /* We have 4 on-time reports so we can proceed */
        uint32_t quality = 100;
        for (i = 0; i < 4; i++) {
            uint32_t current = reports[i]->received_packets * 100 / reports[i]->expected_packets;
            quality = MIN(quality, current);
            free(reports[i]);
        }
        
        if (quality <= 90) {
            LOGGER_WARNING("Stream quality: BAD (%d)", quality);
            return rtp_StateBad;
        } else if (quality >= 99) {
            LOGGER_DEBUG("Stream quality: GOOD (%d)", quality);
            return rtp_StateGood;
        } else {
            LOGGER_DEBUG("Stream quality: NORMAL (%d)", quality);
        }
    }
    return rtp_StateNormal;
}
int rtp_start_receiving(RTPSession* session)
{
    if (session == NULL)
        return -1;
    
    if (m_callback_rtp_packet(session->m, session->friend_number, session->prefix,
        handle_rtp_packet, session) == -1) {
        LOGGER_WARNING("Failed to register rtp receive handler");
        return -1;
    }
    if (m_callback_rtp_packet(session->m, session->friend_number, session->rtcp_session->prefix,
        handle_rtcp_packet, session->rtcp_session) == -1) {
        LOGGER_WARNING("Failed to register rtcp receive handler");
        m_callback_rtp_packet(session->m, session->friend_number, session->prefix, NULL, NULL);
        return -1;
    }
    
    return 0;
}
int rtp_stop_receiving(RTPSession* session)
{
    if (session == NULL)
        return -1;
    
    m_callback_rtp_packet(session->m, session->friend_number, session->prefix, NULL, NULL);
    m_callback_rtp_packet(session->m, session->friend_number, session->rtcp_session->prefix, NULL, NULL); /* RTCP */
    
    return 0;
}
int rtp_send_data ( RTPSession *session, const uint8_t *data, uint16_t length, bool dummy )
{
    if ( !session ) {
        LOGGER_WARNING("No session!");
        return -1;
    }
    
    uint8_t parsed[MAX_RTP_SIZE];
    uint8_t *it;

    RTPHeader header[1] = {0};
    
    ADD_FLAG_VERSION ( header, session->version );
    ADD_FLAG_PADDING ( header, session->padding );
    ADD_FLAG_EXTENSION ( header, session->extension );
    ADD_FLAG_CSRCC ( header, session->cc );
    ADD_SETTING_MARKER ( header, session->marker );
    
    if (dummy)
        ADD_SETTING_PAYLOAD ( header, (session->payload_type + 2) % 128 );
    else
        ADD_SETTING_PAYLOAD ( header, session->payload_type );

    header->sequnum = session->sequnum;
    header->timestamp = current_time_monotonic();
    header->ssrc = session->ssrc;

    int i;
    for ( i = 0; i < session->cc; i++ )
        header->csrc[i] = session->csrc[i];

    header->length = 12 /* Minimum header len */ + ( session->cc * size_32 );
    
    uint32_t parsed_len = length + header->length + 1;
    assert(parsed_len + (session->ext_header ? session->ext_header->length * size_32 : 0) < MAX_RTP_SIZE );

    parsed[0] = session->prefix;
    it = parse_header_out ( header, parsed + 1 );
    
    if ( session->ext_header ) {
        parsed_len += ( 4 /* Minimum ext header len */ + session->ext_header->length * size_32 );
        it = parse_ext_header_out ( session->ext_header, it );
    }

    memcpy(it, data, length);
    
    if ( -1 == send_custom_lossy_packet(session->m, session->friend_number, parsed, parsed_len) ) {
        LOGGER_WARNING("Failed to send full packet (len: %d)! std error: %s", length, strerror(errno));
        return -1;
    }
    
    session->sequnum = session->sequnum >= MAX_SEQU_NUM ? 0 : session->sequnum + 1;
    return 0;
}
void rtp_free_msg ( RTPMessage *msg )
{
    if ( msg->ext_header ) {
        free ( msg->ext_header->table );
        free ( msg->ext_header );
    }
    
    free ( msg->header );
    free ( msg );
}



RTPHeader *parse_header_in ( const uint8_t *payload, int length )
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
    
    if ( GET_FLAG_VERSION(retu) != RTP_VERSION ) {
        /* Deallocate */
        LOGGER_WARNING("Invalid version!");
        free(retu);
        return NULL;
    }

    uint8_t cc = GET_FLAG_CSRCC ( retu );
    int total = 12 /* Minimum header len */ + ( cc * 4 );

    if ( length < total ) {
        LOGGER_WARNING("Length invalid!");
        free(retu);
        return NULL;
    }

    retu->marker_payloadt = *it;
    ++it;
    retu->length = total;


    memcpy(&retu->timestamp, it, sizeof(retu->timestamp));
    it += 4;
    memcpy(&retu->ssrc, it, sizeof(retu->ssrc));
    
    retu->timestamp = ntohl(retu->timestamp);
    retu->ssrc = ntohl(retu->ssrc);

    uint8_t x;
    for ( x = 0; x < cc; x++ ) {
        it += 4;
        memcpy(&retu->csrc[x], it, sizeof(retu->csrc[x]));
        retu->csrc[x] = ntohl(retu->csrc[x]);
    }

    return retu;
}
RTPExtHeader *parse_ext_header_in ( const uint8_t *payload, uint16_t length )
{
    const uint8_t *it = payload;

    RTPExtHeader *retu = calloc(1, sizeof (RTPExtHeader));

    if ( !retu ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    memcpy(&retu->length, it, sizeof(retu->length));
    retu->length = ntohs(retu->length);
    it += 2;
    
    if ( length < ( retu->length * sizeof(uint32_t) ) ) {
        LOGGER_WARNING("Length invalid!");
        free(retu);
        return NULL;
    }
    
    memcpy(&retu->type, it, sizeof(retu->type));
    retu->type = ntohs(retu->type);
    
    it += 2;
    
    if ( !(retu->table = calloc(retu->length, sizeof (uint32_t))) ) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        free(retu);
        return NULL;
    }

    uint16_t x;
    for ( x = 0; x < retu->length; x++ ) {
        it += 4;
        memcpy(retu->table + x, it, sizeof(*retu->table));
        retu->table[x] = ntohl(retu->table[x]);
    }

    return retu;
}
uint8_t *parse_header_out ( const RTPHeader *header, uint8_t *payload )
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
uint8_t *parse_ext_header_out ( const RTPExtHeader *header, uint8_t *payload )
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
int handle_rtp_packet ( Messenger* m, uint32_t friendnumber, const uint8_t* data, uint16_t length, void* object )
{
    RTPSession *session = object;

    if ( !session || length < 13 || length > MAX_RTP_SIZE ) {
        LOGGER_WARNING("No session or invalid length of received buffer!");
        return -1;
    }
    
    RTPHeader* header = parse_header_in ( data + 1, length );

    if ( !header ) {
        LOGGER_WARNING("Could not parse message: Header failed to extract!");
        return -1;
    }
    
    RTPExtHeader* ext_header = NULL;
    
    uint16_t from_pos = header->length + 1;
    uint16_t msg_length = length - from_pos;

    if ( GET_FLAG_EXTENSION ( header ) ) {
        ext_header = parse_ext_header_in ( data + from_pos, length );

        if ( ext_header ) {
            msg_length -= ( 4 /* Minimum ext header len */ + ext_header->length * size_32 );
            from_pos += ( 4 /* Minimum ext header len */ + ext_header->length * size_32 );
        } else { /* Error */
            LOGGER_WARNING("Could not parse message: Ext Header failed to extract!");
            free(header);
            return -1;
        }
    }
    
    if (msg_length > MAX_RTP_SIZE) {
        LOGGER_WARNING("Could not parse message: Invalid length!");
        free(header);
        free(ext_header);
        return -1;
    }
    
    /* Check if message came in late */
    if ( header->sequnum > session->rsequnum || header->timestamp > session->rtimestamp ) {
        /* Not late */
        if (header->sequnum > session->rsequnum)
            session->rtcp_session->last_expected_packets += header->sequnum - session->rsequnum;
        else if (header->sequnum < session->rsequnum)
            session->rtcp_session->last_expected_packets += (header->sequnum + 65535) - session->rsequnum;
        else /* Usual case when transmission starts */
            session->rtcp_session->last_expected_packets ++;
        
        session->rsequnum = header->sequnum;
        session->rtimestamp = header->timestamp;
    }

    session->rtcp_session->last_received_packets ++;
    
    /* Check if the message is dummy. We don't keep dummy messages */
    if (GET_SETTING_PAYLOAD(header) == (session->payload_type + 2) % 128) {
        LOGGER_DEBUG("Received dummy rtp message");
        free(header);
        free(ext_header);
        return 0;
    }
    
    /* Otherwise we will store the message if we have an appropriate handler */
    if (!session->mcb) {
        LOGGER_DEBUG("No handler for the message of %d payload", GET_SETTING_PAYLOAD(header));
        free(header);
        free(ext_header);
        return 0;
    }
    
    RTPMessage *msg = calloc(1, sizeof (RTPMessage) + msg_length);
    
    if ( !msg ) {
        LOGGER_WARNING("Could not parse message: Allocation failed!");
        free(header);
        free(ext_header);
        return -1;
    }
    
    msg->header = header;
    msg->ext_header = ext_header;
    msg->length = msg_length;
    
    memcpy ( msg->data, data + from_pos, msg_length );
    
    return session->mcb (session->cs, msg);
}
int handle_rtcp_packet ( Messenger* m, uint32_t friendnumber, const uint8_t* data, uint16_t length, void* object )
{
    if (length < 9)
        return -1;
    
    RTCPSession* session = object;
    RTCPReport* report = malloc(sizeof(RTCPReport));
    
    memcpy(&report->received_packets, data + 1, 4);
    memcpy(&report->expected_packets, data + 5, 4);
    
    report->received_packets = ntohl(report->received_packets);
    report->expected_packets = ntohl(report->expected_packets);
    
    if (report->expected_packets == 0 || report->received_packets > report->expected_packets) {
        LOGGER_WARNING("Malformed rtcp report! %d %d", report->expected_packets, report->received_packets);
        free(report);
        return 0;
    }
    
    report->timestamp = current_time_monotonic();
    
    free(rb_write(session->pl_stats, report));
    
    LOGGER_DEBUG("Got rtcp report: ex: %d rc: %d", report->expected_packets, report->received_packets);
    return 0;
}
void send_rtcp_report(RTCPSession* session, Messenger* m, uint32_t friendnumber)
{
    if (session->last_expected_packets == 0)
        return;
    
    uint8_t parsed[9];
    parsed[0] = session->prefix;
    
    uint32_t received_packets = htonl(session->last_received_packets);
    uint32_t expected_packets = htonl(session->last_expected_packets);
    
    memcpy(parsed + 1, &received_packets, 4);
    memcpy(parsed + 5, &expected_packets, 4);
    
    if (-1 == send_custom_lossy_packet(m, friendnumber, parsed, sizeof(parsed)))
        LOGGER_WARNING("Failed to send full packet (len: %d)! std error: %s", sizeof(parsed), strerror(errno));
    else {
        LOGGER_DEBUG("Sent rtcp report: ex: %d rc: %d", session->last_expected_packets, session->last_received_packets);
        
        session->last_received_packets = 0;
        session->last_expected_packets = 0;
        session->last_sent_report_ts = current_time_monotonic();
    }
}