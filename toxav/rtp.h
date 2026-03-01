/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_RTP_H
#define C_TOXCORE_TOXAV_RTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"

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

typedef struct RTPHeader RTPHeader;
typedef struct RTPMessage RTPMessage;
typedef struct RTPSession RTPSession;

/* RTPMessage accessors */
const uint8_t *_Nonnull rtp_message_data(const RTPMessage *_Nonnull msg);
uint32_t rtp_message_len(const RTPMessage *_Nonnull msg);
uint8_t rtp_message_pt(const RTPMessage *_Nonnull msg);
uint16_t rtp_message_sequnum(const RTPMessage *_Nonnull msg);
uint64_t rtp_message_flags(const RTPMessage *_Nonnull msg);
uint32_t rtp_message_data_length_full(const RTPMessage *_Nonnull msg);

/* RTPSession accessors */
bool rtp_session_is_receiving_active(const RTPSession *_Nullable session);
uint32_t rtp_session_get_ssrc(const RTPSession *_Nonnull session);
void rtp_session_set_ssrc(RTPSession *_Nonnull session, uint32_t ssrc);

#define USED_RTP_WORKBUFFER_COUNT 3
#define DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT 10

typedef int rtp_m_cb(const Mono_Time *_Nonnull mono_time, void *_Nonnull cs, RTPMessage *_Nonnull msg);

typedef int rtp_send_packet_cb(void *_Nullable user_data, const uint8_t *_Nonnull data, uint16_t length);
typedef void rtp_add_recv_cb(void *_Nullable user_data, uint32_t bytes);
typedef void rtp_add_lost_cb(void *_Nullable user_data, uint32_t bytes);

void rtp_receive_packet(RTPSession *_Nonnull session, const uint8_t *_Nonnull data, size_t length);

/**
 * Serialise an RTPHeader to bytes to be sent over the network.
 *
 * @param rdata A byte array of length RTP_HEADER_SIZE. Does not need to be
 *   initialised. All RTP_HEADER_SIZE bytes will be initialised after a call
 *   to this function.
 * @param header The RTPHeader to serialise.
 */
size_t rtp_header_pack(uint8_t *_Nonnull rdata, const struct RTPHeader *_Nonnull header);

/**
 * Deserialise an RTPHeader from bytes received over the network.
 *
 * @param data A byte array of length RTP_HEADER_SIZE.
 * @param header The RTPHeader to write the unpacked values to.
 */
size_t rtp_header_unpack(const uint8_t *_Nonnull data, struct RTPHeader *_Nonnull header);

RTPSession *_Nullable rtp_new(const Logger *_Nonnull log, int payload_type, Mono_Time *_Nonnull mono_time,
                              rtp_send_packet_cb *_Nullable send_packet, void *_Nullable send_packet_user_data,
                              rtp_add_recv_cb *_Nullable add_recv, rtp_add_lost_cb *_Nullable add_lost, void *_Nullable bwc_user_data,
                              void *_Nonnull cs, rtp_m_cb *_Nonnull mcb);
void rtp_kill(const Logger *_Nonnull log, RTPSession *_Nullable session);
void rtp_allow_receiving_mark(RTPSession *_Nullable session);
void rtp_stop_receiving_mark(RTPSession *_Nullable session);

/**
 * @brief Send a frame of audio or video data, chunked in @ref RTPMessage instances.
 *
 * @param session The A/V session to send the data for.
 * @param data A byte array of length @p length.
 * @param length The number of bytes to send from @p data.
 * @param is_keyframe Whether this video frame is a key frame. If it is an
 *   audio frame, this parameter is ignored.
 */
int rtp_send_data(const Logger *_Nonnull log, RTPSession *_Nonnull session, const uint8_t *_Nonnull data, uint32_t length,
                  bool is_keyframe);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_RTP_H */
