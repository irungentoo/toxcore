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

#include "bwcontroler.h"
#include "../toxcore/Messenger.h"
#include "stdbool.h"

/**
 * Payload type identifier. Also used as rtp callback prefix.
 */
enum {
    rtp_TypeAudio = 192,
    rtp_TypeVideo,
};

struct RTPHeader {
    /* Standard RTP header */
#ifndef WORDS_BIGENDIAN
    uint16_t cc: 4; /* Contributing sources count */
    uint16_t xe: 1; /* Extra header */
    uint16_t pe: 1; /* Padding */
    uint16_t ve: 2; /* Version */

    uint16_t pt: 7; /* Payload type */
    uint16_t ma: 1; /* Marker */
#else
    uint16_t ve: 2; /* Version */
    uint16_t pe: 1; /* Padding */
    uint16_t xe: 1; /* Extra header */
    uint16_t cc: 4; /* Contributing sources count */

    uint16_t ma: 1; /* Marker */
    uint16_t pt: 7; /* Payload type */
#endif

    uint16_t sequnum;
    uint32_t timestamp;
    uint32_t ssrc;
    uint32_t csrc[16];

    /* Non-standard TOX-specific fields */
    uint16_t cpart;/* Data offset of the current part */
    uint16_t tlen; /* Total message lenght */
} __attribute__ ((packed));

/* Check alignment */
typedef char __fail_if_misaligned [ sizeof(struct RTPHeader) == 80 ? 1 : -1 ];

struct RTPMessage {
    uint16_t len;

    struct RTPHeader header;
    uint8_t data[];
} __attribute__ ((packed));

/* Check alignment */
typedef char __fail_if_misaligned [ sizeof(struct RTPMessage) == 82 ? 1 : -1 ];

/**
 * RTP control session.
 */
typedef struct {
    uint8_t  payload_type;
    uint16_t sequnum;      /* Sending sequence number */
    uint16_t rsequnum;     /* Receiving sequence number */
    uint32_t rtimestamp;
    uint32_t ssrc;

    struct RTPMessage *mp; /* Expected parted message */

    Messenger *m;
    uint32_t friend_number;

    BWControler *bwc;
    void *cs;
    int (*mcb) (void *, struct RTPMessage *msg);
} RTPSession;


RTPSession *rtp_new (int payload_type, Messenger *m, uint32_t friend_num,
                     BWControler *bwc, void *cs,
                     int (*mcb) (void *, struct RTPMessage *));
void rtp_kill (RTPSession *session);
int rtp_allow_receiving (RTPSession *session);
int rtp_stop_receiving (RTPSession *session);
int rtp_send_data (RTPSession *session, const uint8_t *data, uint16_t length);

#endif /* RTP_H */
