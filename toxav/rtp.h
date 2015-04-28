/**  rtp.h
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

#ifndef RTP_H
#define RTP_H

#define RTP_VERSION 2

#include "../toxcore/Messenger.h"

#define LOGGED_LOCK(mutex) do { \
    /*LOGGER_DEBUG("Locking mutex: %p", mutex);*/\
    pthread_mutex_lock(mutex);\
    /*LOGGER_DEBUG("Locked mutex: %p", mutex);*/\
} while(0)

#define LOGGED_UNLOCK(mutex) do { \
    /*LOGGER_DEBUG("Unlocking mutex: %p", mutex);*/\
    pthread_mutex_unlock(mutex);\
    /*LOGGER_DEBUG("Unlocked mutex: %p", mutex);*/\
} while(0)

#define MAX_SEQU_NUM 65535
#define MAX_RTP_SIZE 1500

/**
 * Payload type identifier. Also used as rtp callback prefix. (Not dummies)
 */
enum {
    rtp_TypeAudio = 192,
    rtp_TypeVideo,
};

enum {
    rtp_StateBad = -1,
    rtp_StateNormal,
    rtp_StateGood,
};

/** 
 * Standard rtp header.
 */
typedef struct {
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
typedef struct {
    uint16_t  type;          /* Extension profile */
    uint16_t  length;        /* Number of extensions */
    uint32_t *table;         /* Extension's table */
} RTPExtHeader;

/**
 * Standard rtp message.
 */
typedef struct RTPMessage_s {
    RTPHeader    *header;
    RTPExtHeader *ext_header;

    uint32_t      length;
    uint8_t       data[];
} RTPMessage;

/**
 * RTP control session.
 */
typedef struct {
    uint8_t  version;
    uint8_t  padding;
    uint8_t  extension;
    uint8_t  cc;
    uint8_t  marker;
    uint8_t  payload_type;
    uint16_t sequnum;   /* Sending sequence number */
    uint16_t rsequnum;  /* Receiving sequence number */
    uint32_t rtimestamp;
    uint32_t ssrc;
    uint32_t *csrc;

    /* If some additional data must be sent via message
     * apply it here. Only by allocating this member you will be
     * automatically placing it within a message.
     */
    RTPExtHeader *ext_header;

    /* Msg prefix for core to know when recving */
    uint8_t prefix;

    Messenger *m;
    int friend_number;
    struct RTCPSession_s *rtcp_session;

    void *cs;
    int (*mcb) (void*, RTPMessage* msg);
    
} RTPSession;

/**
 * Must be called before calling any other rtp function.
 */
RTPSession *rtp_new ( int payload_type, Messenger *m, int friend_num, void* cs, int (*mcb) (void*, RTPMessage*) );
/**
 * Terminate the session.
 */
void rtp_kill ( RTPSession* session );
/**
 * Do periodical rtp work.
 */
int rtp_do(RTPSession *session);
/**
 * By default rtp is in receiving state
 */
int rtp_start_receiving (RTPSession *session);
/**
 * Pause rtp receiving mode.
 */
int rtp_stop_receiving (RTPSession *session);
/**
 * Sends msg to RTPSession::dest
 */
int rtp_send_data ( RTPSession* session, const uint8_t* data, uint16_t length, bool dummy );
/**
 * Dealloc msg.
 */
void rtp_free_msg ( RTPMessage *msg );


#endif /* RTP_H */
