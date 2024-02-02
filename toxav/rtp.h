/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_RTP_H
#define C_TOXCORE_TOXAV_RTP_H

#include <stdbool.h>

#include "bwcontroller.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/tox.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RTPHeader serialised size in bytes.
 */
#define RTP_HEADER_SIZE 80

/**
 * Number of 32 bit padding fields between @ref RTPHeader::offset_lower and
 * everything before it.
 */
#define RTP_PADDING_FIELDS 11

/**
 * Payload type identifier. Also used as rtp callback prefix.
 */
typedef enum RTP_Type {
    RTP_TYPE_AUDIO = 192,
    RTP_TYPE_VIDEO = 193,
} RTP_Type;

/**
 * A bit mask (up to 64 bits) specifying features of the current frame affecting
 * the behaviour of the decoder.
 */
typedef enum RTPFlags {
    /**
     * Support frames larger than 64KiB. The full 32 bit length and offset are
     * set in @ref RTPHeader::data_length_full and @ref RTPHeader::offset_full.
     */
    RTP_LARGE_FRAME = 1 << 0,
    /**
     * Whether the packet is part of a key frame.
     */
    RTP_KEY_FRAME = 1 << 1,
} RTPFlags;

struct RTPHeader {
    /* Standard RTP header */
    unsigned ve: 2; /* Version has only 2 bits! */
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
     * Bit mask of `RTPFlags` setting features of the current frame.
     */
    uint64_t flags;

    /**
     * The full 32 bit data offset of the current data chunk. The @ref
     * offset_lower data member contains the lower 16 bits of this value. For
     * frames smaller than 64KiB, @ref offset_full and @ref offset_lower are
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
     * Data offset of the current part (lower bits).
     */
    uint16_t offset_lower;
    /**
     * Total message length (lower bits).
     */
    uint16_t data_length_lower;
};

struct RTPMessage {
    /**
     * This is used in the old code that doesn't deal with large frames, i.e.
     * the audio code or receiving code for old 16 bit messages. We use it to
     * record the number of bytes received so far in a multi-part message. The
     * multi-part message in the old code is stored in `RTPSession::mp`.
     */
    uint16_t len;

    struct RTPHeader header;
    uint8_t data[];
};

#define USED_RTP_WORKBUFFER_COUNT 3

/**
 * One slot in the work buffer list. Represents one frame that is currently
 * being assembled.
 */
struct RTPWorkBuffer {
    /**
     * Whether this slot contains a key frame. This is true iff
     * `buf->header.flags & RTP_KEY_FRAME`.
     */
    bool is_keyframe;
    /**
     * The number of bytes received so far, regardless of which pieces. I.e. we
     * could have received the first 1000 bytes and the last 1000 bytes with
     * 4000 bytes in the middle still to come, and this number would be 2000.
     */
    uint32_t received_len;
    /**
     * The message currently being assembled.
     */
    struct RTPMessage *buf;
};

struct RTPWorkBufferList {
    int8_t next_free_entry;
    struct RTPWorkBuffer work_buffer[USED_RTP_WORKBUFFER_COUNT];
};

#define DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT 10

typedef int rtp_m_cb(Mono_Time *mono_time, void *cs, struct RTPMessage *msg);

/**
 * RTP control session.
 */
typedef struct RTPSession {
    uint8_t  payload_type;
    uint16_t sequnum;      /* Sending sequence number */
    uint16_t rsequnum;     /* Receiving sequence number */
    uint32_t rtimestamp;
    uint32_t ssrc; //  this seems to be unused!?
    struct RTPMessage *mp; /* Expected parted message */
    struct RTPWorkBufferList *work_buffer_list;
    uint8_t  first_packets_counter; /* dismiss first few lost video packets */
    Messenger *m;
    Tox *tox;
    uint32_t friend_number;
    BWController *bwc;
    void *cs;
    rtp_m_cb *mcb;
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

RTPSession *rtp_new(int payload_type, Messenger *m, Tox *tox, uint32_t friendnumber,
                    BWController *bwc, void *cs, rtp_m_cb *mcb);
void rtp_kill(RTPSession *session);
int rtp_allow_receiving(RTPSession *session);
int rtp_stop_receiving(RTPSession *session);
/**
 * Send a frame of audio or video data, chunked in @ref RTPMessage instances.
 *
 * @param session The A/V session to send the data for.
 * @param data A byte array of length @p length.
 * @param length The number of bytes to send from @p data.
 * @param is_keyframe Whether this video frame is a key frame. If it is an
 *   audio frame, this parameter is ignored.
 */
int rtp_send_data(RTPSession *session, const uint8_t *data, uint32_t length,
                  bool is_keyframe, const Logger *log);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_RTP_H */
