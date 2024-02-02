/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "rtp.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "bwcontroller.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/util.h"

/**
 * The number of milliseconds we want to keep a keyframe in the buffer for,
 * even though there are no free slots for incoming frames.
 */
#define VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS 15

/**
 * return -1 on failure, 0 on success
 *
 */
static int rtp_send_custom_lossy_packet(Tox *tox, int32_t friendnumber, const uint8_t *data, uint32_t length)
{
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossy_packet(tox, friendnumber, data, (size_t)length, &error);

    if (error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK) {
        return 0;
    }

    return -1;
}

// allocate_len is NOT including header!
static struct RTPMessage *new_message(const struct RTPHeader *header, size_t allocate_len, const uint8_t *data,
                                      uint16_t data_length)
{
    assert(allocate_len >= data_length);
    struct RTPMessage *msg = (struct RTPMessage *)calloc(1, sizeof(struct RTPMessage) + allocate_len);

    if (msg == nullptr) {
        return nullptr;
    }

    msg->len = data_length; // result without header
    msg->header = *header;
    memcpy(msg->data, data, msg->len);
    return msg;
}

/**
 * Instruct the caller to clear slot 0.
 */
#define GET_SLOT_RESULT_DROP_OLDEST_SLOT (-1)

/**
 * Instruct the caller to drop the incoming packet.
 */
#define GET_SLOT_RESULT_DROP_INCOMING (-2)

/**
 * Find the next free slot in work_buffer for the incoming data packet.
 *
 * - If the data packet belongs to a frame that's already in the work_buffer then
 *   use that slot.
 * - If there is no free slot return GET_SLOT_RESULT_DROP_OLDEST_SLOT.
 * - If the data packet is too old return GET_SLOT_RESULT_DROP_INCOMING.
 *
 * If there is a keyframe being assembled in slot 0, keep it a bit longer and
 * do not kick it out right away if all slots are full instead kick out the new
 * incoming interframe.
 */
static int8_t get_slot(const Logger *log, struct RTPWorkBufferList *wkbl, bool is_keyframe,
                       const struct RTPHeader *header, bool is_multipart)
{
    if (is_multipart) {
        // This RTP message is part of a multipart frame, so we try to find an
        // existing slot with the previous parts of the frame in it.
        for (uint8_t i = 0; i < wkbl->next_free_entry; ++i) {
            const struct RTPWorkBuffer *slot = &wkbl->work_buffer[i];

            if ((slot->buf->header.sequnum == header->sequnum) && (slot->buf->header.timestamp == header->timestamp)) {
                // Sequence number and timestamp match, so this slot belongs to
                // the same frame.
                //
                // In reality, these will almost certainly either both match or
                // both not match. Only if somehow there were 65535 frames
                // between, the timestamp will matter.
                return i;
            }
        }
    }

    // The message may or may not be part of a multipart frame.
    //
    // If it is part of a multipart frame, then this is an entirely new frame
    // for which we did not have a slot *or* the frame is so old that its slot
    // has been evicted by now.
    //
    //        |----------- time ----------->
    //        _________________
    // slot 0 |               |
    //        -----------------
    //                     _________________
    // slot 1              |               |
    //                     -----------------
    //                ____________
    // slot 2         |          | -> frame too old, drop
    //                ------------
    //
    //
    //
    //        |----------- time ----------->
    //        _________________
    // slot 0 |               |
    //        -----------------
    //                     _________________
    // slot 1              |               |
    //                     -----------------
    //                              ____________
    // slot 2                       |          | -> ok, start filling in a new slot
    //                              ------------

    // If there is a free slot:
    if (wkbl->next_free_entry < USED_RTP_WORKBUFFER_COUNT) {
        // If there is at least one filled slot:
        if (wkbl->next_free_entry > 0) {
            // Get the most recently filled slot.
            const struct RTPWorkBuffer *slot = &wkbl->work_buffer[wkbl->next_free_entry - 1];

            // If the incoming packet is older than our newest slot, drop it.
            // This is the first situation in the above diagram.
            if (slot->buf->header.timestamp > header->timestamp) {
                LOGGER_DEBUG(log, "workbuffer:2:timestamp too old");
                return GET_SLOT_RESULT_DROP_INCOMING;
            }
        }

        // Not all slots are filled, and the packet is newer than our most
        // recent slot, so it's a new frame we want to start assembling. This is
        // the second situation in the above diagram.
        return wkbl->next_free_entry;
    }

    // If the incoming frame is a key frame, then stop assembling the oldest
    // slot, regardless of whether there was a keyframe in that or not.
    if (is_keyframe) {
        return GET_SLOT_RESULT_DROP_OLDEST_SLOT;
    }

    // The incoming slot is not a key frame, so we look at slot 0 to see what to
    // do next.
    const struct RTPWorkBuffer *slot = &wkbl->work_buffer[0];

    // The incoming frame is not a key frame, but the existing slot 0 is also
    // not a keyframe, so we stop assembling the existing frame and make space
    // for the new one.
    if (!slot->is_keyframe) {
        return GET_SLOT_RESULT_DROP_OLDEST_SLOT;
    }

    // If this key frame is fully received, we also stop assembling and clear
    // slot 0.  This also means sending the frame to the decoder.
    if (slot->received_len == slot->buf->header.data_length_full) {
        return GET_SLOT_RESULT_DROP_OLDEST_SLOT;
    }

    // This is a key frame, not fully received yet, but it's already much older
    // than the incoming frame, so we stop assembling it and send whatever part
    // we did receive to the decoder.
    if (slot->buf->header.timestamp + VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS <= header->timestamp) {
        return GET_SLOT_RESULT_DROP_OLDEST_SLOT;
    }

    // This is a key frame, it's not too old yet, so we keep it in its slot for
    // a little longer.
    LOGGER_INFO(log, "keep KEYFRAME in workbuffer");
    return GET_SLOT_RESULT_DROP_INCOMING;
}

/**
 * Returns an assembled frame (as much data as we currently have for this frame,
 * some pieces may be missing)
 *
 * If there are no frames ready, we return NULL. If this function returns
 * non-NULL, it transfers ownership of the message to the caller, i.e. the
 * caller is responsible for storing it elsewhere or calling `free()`.
 */
static struct RTPMessage *process_frame(const Logger *log, struct RTPWorkBufferList *wkbl, uint8_t slot_id)
{
    assert(wkbl->next_free_entry >= 0);

    if (wkbl->next_free_entry == 0) {
        // There are no frames in any slot.
        return nullptr;
    }

    // Slot 0 contains a key frame, slot_id points at an interframe that is
    // relative to that key frame, so we don't use it yet.
    if (wkbl->work_buffer[0].is_keyframe && slot_id != 0) {
        LOGGER_DEBUG(log, "process_frame:KEYFRAME waiting in slot 0");
        return nullptr;
    }

    // Either slot_id is 0 and slot 0 is a key frame, or there is no key frame
    // in slot 0 (and slot_id is anything).
    struct RTPWorkBuffer *const slot = &wkbl->work_buffer[slot_id];

    // Move ownership of the frame out of the slot into m_new.
    struct RTPMessage *const m_new = slot->buf;
    slot->buf = nullptr;

    assert(wkbl->next_free_entry >= 1 && wkbl->next_free_entry <= USED_RTP_WORKBUFFER_COUNT);

    if (slot_id != wkbl->next_free_entry - 1) {
        // The slot is not the last slot, so we created a gap. We move all the
        // entries after it one step up.
        for (uint8_t i = slot_id; i < wkbl->next_free_entry - 1; ++i) {
            // Move entry (i+1) into entry (i).
            wkbl->work_buffer[i] = wkbl->work_buffer[i + 1];
        }
    }

    // We now have a free entry at the end of the array.
    --wkbl->next_free_entry;

    // Clear the newly freed entry.
    const struct RTPWorkBuffer empty = {0};
    wkbl->work_buffer[wkbl->next_free_entry] = empty;

    // Move ownership of the frame to the caller.
    return m_new;
}

/**
 * @param log A logger.
 * @param wkbl The list of in-progress frames, i.e. all the slots.
 * @param slot_id The slot we want to fill the data into.
 * @param is_keyframe Whether the data is part of a key frame.
 * @param header The RTP header from the incoming packet.
 * @param incoming_data The pure payload without header.
 * @param incoming_data_length The length in bytes of the incoming data payload.
 */
static bool fill_data_into_slot(const Logger *log, struct RTPWorkBufferList *wkbl, const uint8_t slot_id,
                                bool is_keyframe, const struct RTPHeader *header,
                                const uint8_t *incoming_data, uint16_t incoming_data_length)
{
    // We're either filling the data into an existing slot, or in a new one that
    // is the next free entry.
    assert(slot_id <= wkbl->next_free_entry);
    struct RTPWorkBuffer *const slot = &wkbl->work_buffer[slot_id];

    assert(header != nullptr);
    assert(is_keyframe == (bool)((header->flags & RTP_KEY_FRAME) != 0));

    if (slot->received_len == 0) {
        assert(slot->buf == nullptr);

        // No data for this slot has been received, yet, so we create a new
        // message for it with enough memory for the entire frame.
        struct RTPMessage *msg = (struct RTPMessage *)calloc(1, sizeof(struct RTPMessage) + header->data_length_full);

        if (msg == nullptr) {
            LOGGER_ERROR(log, "Out of memory while trying to allocate for frame of size %u",
                         (unsigned)header->data_length_full);
            // Out of memory: throw away the incoming data.
            return false;
        }

        // Unused in the new video receiving code, as it's 16 bit and can't hold
        // the full length of large frames. Instead, we use slot->received_len.
        msg->len = 0;
        msg->header = *header;

        slot->buf = msg;
        slot->is_keyframe = is_keyframe;
        slot->received_len = 0;

        assert(wkbl->next_free_entry < USED_RTP_WORKBUFFER_COUNT);
        ++wkbl->next_free_entry;
    }

    // We already checked this when we received the packet, but we rely on it
    // here, so assert again.
    assert(header->offset_full < header->data_length_full);

    // Copy the incoming chunk of data into the correct position in the full
    // frame data array.
    memcpy(
        slot->buf->data + header->offset_full,
        incoming_data,
        incoming_data_length
    );

    // Update the total received length of this slot.
    slot->received_len += incoming_data_length;

    // Update received length also in the header of the message, for later use.
    slot->buf->header.received_length_full = slot->received_len;

    return slot->received_len == header->data_length_full;
}

static void update_bwc_values(const Logger *log, RTPSession *session, const struct RTPMessage *msg)
{
    if (session->first_packets_counter < DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT) {
        ++session->first_packets_counter;
    } else {
        const uint32_t data_length_full = msg->header.data_length_full; // without header
        const uint32_t received_length_full = msg->header.received_length_full; // without header
        bwc_add_recv(session->bwc, data_length_full);

        if (received_length_full < data_length_full) {
            LOGGER_DEBUG(log, "BWC: full length=%u received length=%d", data_length_full, received_length_full);
            bwc_add_lost(session->bwc, data_length_full - received_length_full);
        }
    }
}

/**
 * Handle a single RTP video packet.
 *
 * The packet may or may not be part of a multipart frame. This function will
 * find out and handle it appropriately.
 *
 * @param session The current RTP session with:
 *   <code>
 *   session->mcb == vc_queue_message() // this function is called from here
 *   session->mp == struct RTPMessage *
 *   session->cs == call->video.second // == VCSession created by vc_new() call
 *   </code>
 * @param header The RTP header deserialised from the packet.
 * @param incoming_data The packet data *not* header, i.e. this is the actual
 *   payload.
 * @param incoming_data_length The packet length *not* including header, i.e.
 *   this is the actual payload length.
 * @param log A logger.
 *
 * @retval -1 on error.
 * @retval 0 on success.
 */
static int handle_video_packet(RTPSession *session, const struct RTPHeader *header,
                               const uint8_t *incoming_data, uint16_t incoming_data_length, const Logger *log)
{
    // Full frame length in bytes. The frame may be split into multiple packets,
    // but this value is the complete assembled frame size.
    const uint32_t full_frame_length = header->data_length_full;

    // Current offset in the frame. If this is the first packet of a multipart
    // frame or it's not a multipart frame, then this value is 0.
    const uint32_t offset = header->offset_full; // without header

    // The sender tells us whether this is a key frame.
    const bool is_keyframe = (header->flags & RTP_KEY_FRAME) != 0;

    LOGGER_DEBUG(log, "-- handle_video_packet -- full lens=%u len=%u offset=%u is_keyframe=%s",
                 (unsigned)incoming_data_length, (unsigned)full_frame_length, (unsigned)offset, is_keyframe ? "K" : ".");
    LOGGER_DEBUG(log, "wkbl->next_free_entry:003=%d", session->work_buffer_list->next_free_entry);

    const bool is_multipart = full_frame_length != incoming_data_length;

    /* The message was sent in single part */
    int8_t slot_id = get_slot(log, session->work_buffer_list, is_keyframe, header, is_multipart);
    LOGGER_DEBUG(log, "slot num=%d", slot_id);

    // get_slot told us to drop the packet, so we ignore it.
    if (slot_id == GET_SLOT_RESULT_DROP_INCOMING) {
        return -1;
    }

    // get_slot said there is no free slot.
    if (slot_id == GET_SLOT_RESULT_DROP_OLDEST_SLOT) {
        LOGGER_DEBUG(log, "there was no free slot, so we process the oldest frame");
        // We now own the frame.
        struct RTPMessage *m_new = process_frame(log, session->work_buffer_list, 0);

        // The process_frame function returns NULL if there is no slot 0, i.e.
        // the work buffer list is completely empty. It can't be empty, because
        // get_slot just told us it's full, so process_frame must return non-null.
        assert(m_new != nullptr);

        LOGGER_DEBUG(log, "-- handle_video_packet -- CALLBACK-001a b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
        update_bwc_values(log, session, m_new);
        // Pass ownership of m_new to the callback.
        session->mcb(session->m->mono_time, session->cs, m_new);
        // Now we no longer own m_new.
        m_new = nullptr;

        // Now we must have a free slot, so we either get that slot, i.e. >= 0,
        // or get told to drop the incoming packet if it's too old.
        slot_id = get_slot(log, session->work_buffer_list, is_keyframe, header, /* is_multipart */false);

        if (slot_id == GET_SLOT_RESULT_DROP_INCOMING) {
            // The incoming frame is too old, so we drop it.
            return -1;
        }
    }

    // We must have a valid slot here.
    assert(slot_id >= 0);

    LOGGER_DEBUG(log, "fill_data_into_slot.1");

    // fill in this part into the slot buffer at the correct offset
    if (!fill_data_into_slot(
                log,
                session->work_buffer_list,
                slot_id,
                is_keyframe,
                header,
                incoming_data,
                incoming_data_length)) {
        // Memory allocation failed. Return error.
        return -1;
    }

    struct RTPMessage *m_new = process_frame(log, session->work_buffer_list, slot_id);

    if (m_new != nullptr) {
        LOGGER_DEBUG(log, "-- handle_video_packet -- CALLBACK-003a b0=%d b1=%d", (int)m_new->data[0], (int)m_new->data[1]);
        update_bwc_values(log, session, m_new);
        session->mcb(session->m->mono_time, session->cs, m_new);

        m_new = nullptr;
    }

    return 0;
}

/**
 * @retval -1 on error.
 * @retval 0 on success.
 */
static int handle_rtp_packet(Messenger *m, uint32_t friend_number, const uint8_t *data, uint16_t length, void *object)
{
    RTPSession *session = (RTPSession *)object;

    if (session == nullptr || length < RTP_HEADER_SIZE + 1) {
        LOGGER_WARNING(m->log, "No session or invalid length of received buffer!");
        return -1;
    }

    // Get the packet type.
    const uint8_t packet_type = data[0];
    ++data;
    --length;

    // Unpack the header.
    struct RTPHeader header;
    rtp_header_unpack(data, &header);

    if (header.pt != packet_type % 128) {
        LOGGER_WARNING(m->log, "RTPHeader packet type and Tox protocol packet type did not agree: %d != %d",
                       header.pt, packet_type % 128);
        return -1;
    }

    if (header.pt != session->payload_type % 128) {
        LOGGER_WARNING(m->log, "RTPHeader packet type does not match this session's payload type: %d != %d",
                       header.pt, session->payload_type % 128);
        return -1;
    }

    if ((header.flags & RTP_LARGE_FRAME) != 0 && header.offset_full >= header.data_length_full) {
        LOGGER_ERROR(m->log, "Invalid video packet: frame offset (%u) >= full frame length (%u)",
                     (unsigned)header.offset_full, (unsigned)header.data_length_full);
        return -1;
    }

    if (header.offset_lower >= header.data_length_lower) {
        LOGGER_ERROR(m->log, "Invalid old protocol video packet: frame offset (%u) >= full frame length (%u)",
                     (unsigned)header.offset_lower, (unsigned)header.data_length_lower);
        return -1;
    }

    LOGGER_DEBUG(m->log, "header.pt %d, video %d", (uint8_t)header.pt, RTP_TYPE_VIDEO % 128);

    // The sender uses the new large-frame capable protocol and is sending a
    // video packet.
    if ((header.flags & RTP_LARGE_FRAME) != 0 && header.pt == (RTP_TYPE_VIDEO % 128)) {
        return handle_video_packet(session, &header, data + RTP_HEADER_SIZE, length - RTP_HEADER_SIZE, m->log);
    }

    // everything below here is for the old 16 bit protocol ------------------

    if (header.data_length_lower == length - RTP_HEADER_SIZE) {
        /* The message is sent in single part */

        /* Message is not late; pick up the latest parameters */
        session->rsequnum = header.sequnum;
        session->rtimestamp = header.timestamp;
        bwc_add_recv(session->bwc, length);

        /* Invoke processing of active multiparted message */
        if (session->mp != nullptr) {
            session->mcb(session->m->mono_time, session->cs, session->mp);
            session->mp = nullptr;
        }

        /* The message came in the allowed time;
         */

        return session->mcb(session->m->mono_time, session->cs, new_message(&header, length - RTP_HEADER_SIZE,
                            data + RTP_HEADER_SIZE, length - RTP_HEADER_SIZE));
    }

    /* The message is sent in multiple parts */

    if (session->mp != nullptr) {
        /* There are 2 possible situations in this case:
         *      1) being that we got the part of already processing message.
         *      2) being that we got the part of a new/old message.
         *
         * We handle them differently as we only allow a single multiparted
         * processing message
         */
        if (session->mp->header.sequnum == header.sequnum &&
                session->mp->header.timestamp == header.timestamp) {
            /* First case */

            /* Make sure we have enough allocated memory */
            if (session->mp->header.data_length_lower - session->mp->len < length - RTP_HEADER_SIZE ||
                    session->mp->header.data_length_lower <= header.offset_lower) {
                /* There happened to be some corruption on the stream;
                 * continue wihtout this part
                 */
                return 0;
            }

            memcpy(session->mp->data + header.offset_lower, data + RTP_HEADER_SIZE,
                   length - RTP_HEADER_SIZE);
            session->mp->len += length - RTP_HEADER_SIZE;
            bwc_add_recv(session->bwc, length);

            if (session->mp->len == session->mp->header.data_length_lower) {
                /* Received a full message; now push it for the further
                 * processing.
                 */
                session->mcb(session->m->mono_time, session->cs, session->mp);
                session->mp = nullptr;
            }
        } else {
            /* Second case */
            if (session->mp->header.timestamp > header.timestamp) {
                /* The received message part is from the old message;
                 * discard it.
                 */
                return 0;
            }

            /* Push the previous message for processing */
            session->mcb(session->m->mono_time, session->cs, session->mp);

            session->mp = nullptr;
            goto NEW_MULTIPARTED;
        }
    } else {
        /* In this case threat the message as if it was received in order
         */
        /* This is also a point for new multiparted messages */
NEW_MULTIPARTED:

        /* Message is not late; pick up the latest parameters */
        session->rsequnum = header.sequnum;
        session->rtimestamp = header.timestamp;
        bwc_add_recv(session->bwc, length);

        /* Store message.
         */
        session->mp = new_message(&header, header.data_length_lower, data + RTP_HEADER_SIZE, length - RTP_HEADER_SIZE);

        if (session->mp != nullptr) {
            memmove(session->mp->data + header.offset_lower, session->mp->data, session->mp->len);
        } else {
            LOGGER_WARNING(m->log, "new_message() returned a null pointer");
            return -1;
        }
    }

    return 0;
}

size_t rtp_header_pack(uint8_t *const rdata, const struct RTPHeader *header)
{
    uint8_t *p = rdata;
    *p = (header->ve & 3) << 6
         | (header->pe & 1) << 5
         | (header->xe & 1) << 4
         | (header->cc & 0xf);
    ++p;
    *p = (header->ma & 1) << 7
         | (header->pt & 0x7f);
    ++p;

    p += net_pack_u16(p, header->sequnum);
    p += net_pack_u32(p, header->timestamp);
    p += net_pack_u32(p, header->ssrc);
    p += net_pack_u64(p, header->flags);
    p += net_pack_u32(p, header->offset_full);
    p += net_pack_u32(p, header->data_length_full);
    p += net_pack_u32(p, header->received_length_full);

    for (size_t i = 0; i < RTP_PADDING_FIELDS; ++i) {
        p += net_pack_u32(p, 0);
    }

    p += net_pack_u16(p, header->offset_lower);
    p += net_pack_u16(p, header->data_length_lower);
    assert(p == rdata + RTP_HEADER_SIZE);
    return p - rdata;
}

size_t rtp_header_unpack(const uint8_t *data, struct RTPHeader *header)
{
    const uint8_t *p = data;
    header->ve = (*p >> 6) & 3;
    header->pe = (*p >> 5) & 1;
    header->xe = (*p >> 4) & 1;
    header->cc = *p & 0xf;
    ++p;

    header->ma = (*p >> 7) & 1;
    header->pt = *p & 0x7f;
    ++p;

    p += net_unpack_u16(p, &header->sequnum);
    p += net_unpack_u32(p, &header->timestamp);
    p += net_unpack_u32(p, &header->ssrc);
    p += net_unpack_u64(p, &header->flags);
    p += net_unpack_u32(p, &header->offset_full);
    p += net_unpack_u32(p, &header->data_length_full);
    p += net_unpack_u32(p, &header->received_length_full);

    p += sizeof(uint32_t) * RTP_PADDING_FIELDS;

    p += net_unpack_u16(p, &header->offset_lower);
    p += net_unpack_u16(p, &header->data_length_lower);
    assert(p == data + RTP_HEADER_SIZE);
    return p - data;
}

RTPSession *rtp_new(int payload_type, Messenger *m, Tox *tox, uint32_t friendnumber,
                    BWController *bwc, void *cs, rtp_m_cb *mcb)
{
    assert(mcb != nullptr);
    assert(cs != nullptr);
    assert(m != nullptr);

    RTPSession *session = (RTPSession *)calloc(1, sizeof(RTPSession));

    if (session == nullptr) {
        LOGGER_WARNING(m->log, "Alloc failed! Program might misbehave!");
        return nullptr;
    }

    session->work_buffer_list = (struct RTPWorkBufferList *)calloc(1, sizeof(struct RTPWorkBufferList));

    if (session->work_buffer_list == nullptr) {
        LOGGER_ERROR(m->log, "out of memory while allocating work buffer list");
        free(session);
        return nullptr;
    }

    // First entry is free.
    session->work_buffer_list->next_free_entry = 0;

    session->ssrc = payload_type == RTP_TYPE_VIDEO ? 0 : random_u32(m->rng);
    session->payload_type = payload_type;
    session->m = m;
    session->tox = tox;
    session->friend_number = friendnumber;

    // set NULL just in case
    session->mp = nullptr;
    session->first_packets_counter = 1;

    /* Also set payload type as prefix */
    session->bwc = bwc;
    session->cs = cs;
    session->mcb = mcb;

    if (-1 == rtp_allow_receiving(session)) {
        LOGGER_WARNING(m->log, "Failed to start rtp receiving mode");
        free(session->work_buffer_list);
        free(session);
        return nullptr;
    }

    return session;
}

void rtp_kill(RTPSession *session)
{
    if (session == nullptr) {
        return;
    }

    LOGGER_DEBUG(session->m->log, "Terminated RTP session: %p", (void *)session);
    rtp_stop_receiving(session);

    LOGGER_DEBUG(session->m->log, "Terminated RTP session V3 work_buffer_list->next_free_entry: %d",
                 (int)session->work_buffer_list->next_free_entry);

    for (int8_t i = 0; i < session->work_buffer_list->next_free_entry; ++i) {
        free(session->work_buffer_list->work_buffer[i].buf);
    }
    free(session->work_buffer_list);
    free(session);
}

int rtp_allow_receiving(RTPSession *session)
{
    if (session == nullptr) {
        return -1;
    }

    if (m_callback_rtp_packet(session->m, session->friend_number, session->payload_type,
                              handle_rtp_packet, session) == -1) {
        LOGGER_WARNING(session->m->log, "Failed to register rtp receive handler");
        return -1;
    }

    LOGGER_DEBUG(session->m->log, "Started receiving on session: %p", (void *)session);
    return 0;
}

int rtp_stop_receiving(RTPSession *session)
{
    if (session == nullptr) {
        return -1;
    }

    m_callback_rtp_packet(session->m, session->friend_number, session->payload_type, nullptr, nullptr);

    LOGGER_DEBUG(session->m->log, "Stopped receiving on session: %p", (void *)session);
    return 0;
}

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
                  bool is_keyframe, const Logger *log)
{
    if (session == nullptr) {
        LOGGER_ERROR(log, "No session!");
        return -1;
    }

    struct RTPHeader header = {0};

    header.ve = 2;  // this is unused in toxav

    header.pe = 0;

    header.xe = 0;

    header.cc = 0;

    header.ma = 0;

    header.pt = session->payload_type % 128;

    header.sequnum = session->sequnum;

    header.timestamp = current_time_monotonic(session->m->mono_time);

    header.ssrc = session->ssrc;

    header.offset_lower = 0;

    // here the highest bits gets stripped anyway, no need to do keyframe bit magic here!
    header.data_length_lower = length;

    if (session->payload_type == RTP_TYPE_VIDEO) {
        header.flags = RTP_LARGE_FRAME;
    }

    uint16_t length_safe = (uint16_t)length;

    if (length > UINT16_MAX) {
        length_safe = UINT16_MAX;
    }

    header.data_length_lower = length_safe;
    header.data_length_full = length; // without header
    header.offset_lower = 0;
    header.offset_full = 0;

    if (is_keyframe) {
        header.flags |= RTP_KEY_FRAME;
    }

    const uint16_t rdata_size = length + RTP_HEADER_SIZE + 1;
    VLA(uint8_t, rdata, rdata_size);
    memset(rdata, 0, rdata_size);
    rdata[0] = session->payload_type;  // packet id == payload_type

    if (MAX_CRYPTO_DATA_SIZE > (length + RTP_HEADER_SIZE + 1)) {
        /*
         * The length is lesser than the maximum allowed length (including header)
         * Send the packet in single piece.
         */
        rtp_header_pack(rdata + 1, &header);
        memcpy(rdata + 1 + RTP_HEADER_SIZE, data, length);

        if (-1 == rtp_send_custom_lossy_packet(session->tox, session->friend_number, rdata, rdata_size)) {
            char *netstrerror = net_new_strerror(net_error());
            LOGGER_WARNING(session->m->log, "RTP send failed (len: %u)! net error: %s",
                           rdata_size, netstrerror);
            net_kill_strerror(netstrerror);
        }
    } else {
        /*
         * The length is greater than the maximum allowed length (including header)
         * Send the packet in multiple pieces.
         */
        uint32_t sent = 0;
        uint16_t piece = MAX_CRYPTO_DATA_SIZE - (RTP_HEADER_SIZE + 1);

        while ((length - sent) + RTP_HEADER_SIZE + 1 > MAX_CRYPTO_DATA_SIZE) {
            rtp_header_pack(rdata + 1, &header);
            memcpy(rdata + 1 + RTP_HEADER_SIZE, data + sent, piece);

            if (-1 == rtp_send_custom_lossy_packet(session->tox, session->friend_number,
                                                   rdata, piece + RTP_HEADER_SIZE + 1)) {
                char *netstrerror = net_new_strerror(net_error());
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! net error: %s",
                               piece + RTP_HEADER_SIZE + 1, netstrerror);
                net_kill_strerror(netstrerror);
            }

            sent += piece;
            header.offset_lower = sent;
            header.offset_full = sent; // raw data offset, without any header
        }

        /* Send remaining */
        piece = length - sent;

        if (piece != 0) {
            rtp_header_pack(rdata + 1, &header);
            memcpy(rdata + 1 + RTP_HEADER_SIZE, data + sent, piece);

            if (-1 == rtp_send_custom_lossy_packet(session->tox, session->friend_number, rdata,
                                                   piece + RTP_HEADER_SIZE + 1)) {
                char *netstrerror = net_new_strerror(net_error());
                LOGGER_WARNING(session->m->log, "RTP send failed (len: %d)! net error: %s",
                               piece + RTP_HEADER_SIZE + 1, netstrerror);
                net_kill_strerror(netstrerror);
            }
        }
    }

    ++session->sequnum;
    return 0;
}
