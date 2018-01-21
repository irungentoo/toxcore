/*
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef RTP_H
#define RTP_H

#include "bwcontroller.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RTPHeader serialised size in bytes.
 */
#define RTP_HEADER_SIZE 80

/**
 * Payload type identifier. Also used as rtp callback prefix.
 */
enum {
    rtp_TypeAudio = 192,
    rtp_TypeVideo = 193,
};

/**
 * A bit mask (up to 64 bits) specifying features of the current frame affecting
 * the behaviour of the decoder.
 */
enum RTPFlags {
    /**
     * Support frames larger than 64KiB. The full 32 bit length and offset are
     * set in \ref RTPHeader::data_length_full and \ref RTPHeader::offset_full.
     */
    RTP_LARGE_FRAME = 1 << 0,
    /**
     * Whether the packet is part of a key frame.
     */
    RTP_KEY_FRAME = 1 << 1,
};

struct RTPHeader {
    /* Standard RTP header */
    unsigned protocol_version: 2; /* Version has only 2 bits! */
    unsigned pe: 1; /* Padding */
    unsigned xe: 1; /* Extra header */
    unsigned cc: 4; /* Contributing sources count */

    unsigned ma: 1; /* Marker */
    unsigned pt: 7; /* Payload type */

    uint16_t sequnum;
    uint32_t timestamp;
    uint32_t ssrc;

    /* Non-standard Tox-specific fields */

    /**
     * Bit mask of \ref RTPFlags setting features of the current frame.
     */
    uint64_t flags;

    /**
     * The full 32 bit data offset of the current data chunk. The \ref
     * offset_lower data member contains the lower 16 bits of this value. For
     * frames smaller than 64KiB, \ref offset_full and \ref offset_lower are
     * equal.
     */
    uint32_t offset_full;
    /**
     * The full 32 bit payload length without header and packet id.
     */
    uint32_t data_length_full;
    /**
     * Only the receiver uses this field (why do we have this?).
     */
    uint32_t received_length_full;

    /**
     * Unused fields. If you want to add more information to this header, remove
     * one csrc and add the appropriate number of fields in its place.
     */
    uint32_t csrc[11];

    /**
     * Data offset of the current part (lower bits).
     */
    uint16_t offset_lower;
    /**
     * Total message length (lower bits).
     */
    uint16_t data_length_lower;
};

struct RTPMessage {
    uint16_t len;

    struct RTPHeader header;
    uint8_t data[];
};

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

    BWController *bwc;
    void *cs;
    int (*mcb)(void *, struct RTPMessage *msg);
} RTPSession;

/**
 * Serialise an RTPHeader to bytes to be sent over the network.
 *
 * @param rdata A byte array of length RTP_HEADER_SIZE. Does not need to be
 *   initialised. All RTP_HEADER_SIZE bytes will be initialised after a call
 *   to this function.
 * @param header The RTPHeader to serialise.
 */
size_t rtp_header_pack(uint8_t *rdata, const struct RTPHeader *header);

/**
 * Deserialise an RTPHeader from bytes received over the network.
 *
 * @param data A byte array of length RTP_HEADER_SIZE.
 * @param header The RTPHeader to write the unpacked values to.
 */
size_t rtp_header_unpack(const uint8_t *data, struct RTPHeader *header);

RTPSession *rtp_new(int payload_type, Messenger *m, uint32_t friendnumber,
                    BWController *bwc, void *cs,
                    int (*mcb)(void *, struct RTPMessage *));
void rtp_kill(RTPSession *session);
int rtp_allow_receiving(RTPSession *session);
int rtp_stop_receiving(RTPSession *session);
int rtp_send_data(RTPSession *session, const uint8_t *data, uint16_t length, Logger *log);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif /* RTP_H */
