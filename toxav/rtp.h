/**  rtp.h
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

#ifndef __TOXRTP
#define __TOXRTP

#define RTP_VERSION 2
#include <inttypes.h>
// #include <pthread.h>

#include "../toxcore/Messenger.h"

#define MAX_SEQU_NUM 65535
#define MAX_RTP_SIZE 65535

typedef enum {
    rtp_ErrorSending = -40
} RTPError;
/**
 * Standard rtp header
 */
typedef struct _RTPHeader {
    uint8_t  flags;             /* Version(2),Padding(1), Ext(1), Cc(4) */
    uint8_t  marker_payloadt;   /* Marker(1), PlayLoad Type(7) */
    uint16_t sequnum;           /* Sequence Number */
    uint32_t timestamp;         /* Timestamp */
    uint32_t ssrc;              /* SSRC */
    uint32_t csrc[16];          /* CSRC's table */
    uint32_t length;            /* Length of the header in payload string. */

} RTPHeader;

/**
 * Standard rtp extension header.
 */
typedef struct _RTPExtHeader {
    uint16_t  type;          /* Extension profile */
    uint16_t  length;        /* Number of extensions */
    uint32_t *table;         /* Extension's table */

} RTPExtHeader;

/**
 * Standard rtp message.
 */
typedef struct _RTPMessage {
    RTPHeader    *header;
    RTPExtHeader *ext_header;

    uint8_t       data[MAX_RTP_SIZE];
    uint32_t      length;

    struct _RTPMessage   *next;
} RTPMessage;

/**
 * RTP control session.
 */
typedef struct _RTPSession {
    uint8_t         version;
    uint8_t         padding;
    uint8_t         extension;
    uint8_t         cc;
    uint8_t         marker;
    uint8_t         payload_type;
    uint16_t        sequnum;   /* Set when sending */
    uint16_t        rsequnum;  /* Check when recving msg */
    uint32_t        timestamp;
    uint32_t        ssrc;
    uint32_t       *csrc;

    /* If some additional data must be sent via message
     * apply it here. Only by allocating this member you will be
     * automatically placing it within a message.
     */
    RTPExtHeader   *ext_header;

    /* Msg prefix for core to know when recving */
    uint8_t         prefix;

    int             dest;

    struct _CSSession *cs;

} RTPSession;

/**
 * Must be called before calling any other rtp function.
 */
RTPSession *rtp_new ( int payload_type, Messenger *messenger, int friend_num );

/**
 * Terminate the session.
 */
void rtp_kill ( RTPSession *session, Messenger *messenger );

/**
 * Sends msg to _RTPSession::dest
 */
int rtp_send_msg ( RTPSession *session, Messenger *messenger, const uint8_t *data, uint16_t length );

/**
 * Dealloc msg.
 */
void rtp_free_msg ( RTPSession *session, RTPMessage *msg );



#endif /* __TOXRTP */
