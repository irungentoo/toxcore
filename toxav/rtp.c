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

#include "rtp.h"
#include "bwcontroller.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"
#include "../toxcore/Messenger.h"

#include <stdlib.h>
#include <assert.h>


int handle_rtp_packet (Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object);


RTPSession *rtp_new (int payload_type, Messenger *m, uint32_t friendnumber,
                     BWController *bwc, void *cs,
                     int (*mcb) (void *, struct RTPMessage *))
{
    assert(mcb);
    assert(cs);
    assert(m);

    RTPSession *retu = calloc(1, sizeof(RTPSession));

    if (!retu) {
        LOGGER_WARNING("Alloc failed! Program might misbehave!");
        return NULL;
    }

    retu->ssrc = random_int();
    retu->payload_type = payload_type;

    retu->m = m;
    retu->friend_number = friendnumber;

    /* Also set payload type as prefix */

    retu->bwc = bwc;
    retu->cs = cs;
    retu->mcb = mcb;

    if (-1 == rtp_allow_receiving(retu)) {
        LOGGER_WARNING("Failed to start rtp receiving mode");
        free(retu);
        return NULL;
    }

    return retu;
}
void rtp_kill (RTPSession *session)
{
    if (!session)
        return;

    LOGGER_DEBUG("Terminated RTP session: %p", session);

    rtp_stop_receiving (session);
    free (session);
}
int rtp_allow_receiving(RTPSession *session)
{
    if (session == NULL)
        return -1;

    if (m_callback_rtp_packet(session->m, session->friend_number, session->payload_type,
                              handle_rtp_packet, session) == -1) {
        LOGGER_WARNING("Failed to register rtp receive handler");
        return -1;
    }

    LOGGER_DEBUG("Started receiving on session: %p", session);
    return 0;
}
int rtp_stop_receiving(RTPSession *session)
{
    if (session == NULL)
        return -1;

    m_callback_rtp_packet(session->m, session->friend_number, session->payload_type, NULL, NULL);

    LOGGER_DEBUG("Stopped receiving on session: %p", session);
    return 0;
}
int rtp_send_data (RTPSession *session, const uint8_t *data, uint16_t length)
{
    if (!session) {
        LOGGER_WARNING("No session!");
        return -1;
    }

    uint8_t rdata[length + sizeof(struct RTPHeader) + 1];
    memset(rdata, 0, sizeof(rdata));

    rdata[0] = session->payload_type;

    struct RTPHeader *header = (struct RTPHeader *)(rdata  + 1);

    header->ve = 2;
    header->pe = 0;
    header->xe = 0;
    header->cc = 0;

    header->ma = 0;
    header->pt = session->payload_type % 128;

    header->sequnum = htons(session->sequnum);
    header->timestamp = htonl(current_time_monotonic());
    header->ssrc = htonl(session->ssrc);

    header->cpart = 0;
    header->tlen = htons(length);

    if (MAX_CRYPTO_DATA_SIZE > length + sizeof(struct RTPHeader) + 1) {

        /**
         * The lenght is lesser than the maximum allowed lenght (including header)
         * Send the packet in single piece.
         */

        memcpy(rdata + 1 + sizeof(struct RTPHeader), data, length);

        if (-1 == send_custom_lossy_packet(session->m, session->friend_number, rdata, sizeof(rdata)))
            LOGGER_WARNING("RTP send failed (len: %d)! std error: %s", sizeof(rdata), strerror(errno));
    } else {

        /**
         * The lenght is greater than the maximum allowed lenght (including header)
         * Send the packet in multiple pieces.
         */

        uint16_t sent = 0;
        uint16_t piece = MAX_CRYPTO_DATA_SIZE - (sizeof(struct RTPHeader) + 1);

        while ((length - sent) + sizeof(struct RTPHeader) + 1 > MAX_CRYPTO_DATA_SIZE) {
            memcpy(rdata + 1 + sizeof(struct RTPHeader), data + sent, piece);

            if (-1 == send_custom_lossy_packet(session->m, session->friend_number,
                                               rdata, piece + sizeof(struct RTPHeader) + 1))
                LOGGER_WARNING("RTP send failed (len: %d)! std error: %s",
                               piece + sizeof(struct RTPHeader) + 1, strerror(errno));

            sent += piece;
            header->cpart = htons(sent);
        }

        /* Send remaining */
        piece = length - sent;

        if (piece) {
            memcpy(rdata + 1 + sizeof(struct RTPHeader), data + sent, piece);

            if (-1 == send_custom_lossy_packet(session->m, session->friend_number, rdata,
                                               piece + sizeof(struct RTPHeader) + 1))
                LOGGER_WARNING("RTP send failed (len: %d)! std error: %s",
                               piece + sizeof(struct RTPHeader) + 1, strerror(errno));
        }
    }

    session->sequnum ++;
    return 0;
}


bool chloss (const RTPSession *session, const struct RTPHeader *header)
{
    if (ntohl(header->timestamp) < session->rtimestamp) {
        uint16_t hosq, lost = 0;

        hosq = ntohs(header->sequnum);

        lost = (hosq > session->rsequnum) ?
               (session->rsequnum + 65535) - hosq :
               session->rsequnum - hosq;

        fprintf (stderr, "Lost packet\n");

        while (lost --)
            bwc_add_lost(session->bwc , 0);

        return true;
    }

    return false;
}
struct RTPMessage *new_message (size_t allocate_len, const uint8_t *data, uint16_t data_length)
{
    assert(allocate_len >= data_length);

    struct RTPMessage *msg = calloc(sizeof(struct RTPMessage) + (allocate_len - sizeof(struct RTPHeader)), 1);

    msg->len = data_length - sizeof(struct RTPHeader);
    memcpy(&msg->header, data, data_length);

    msg->header.sequnum = ntohs(msg->header.sequnum);
    msg->header.timestamp = ntohl(msg->header.timestamp);
    msg->header.ssrc = ntohl(msg->header.ssrc);

    msg->header.cpart = ntohs(msg->header.cpart);
    msg->header.tlen = ntohs(msg->header.tlen);

    return msg;
}
int handle_rtp_packet (Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
{
    (void) m;
    (void) friendnumber;

    RTPSession *session = object;

    data ++;
    length--;

    if (!session || length < sizeof (struct RTPHeader)) {
        LOGGER_WARNING("No session or invalid length of received buffer!");
        return -1;
    }

    const struct RTPHeader *header = (struct RTPHeader *) data;

    if (header->pt != session->payload_type % 128) {
        LOGGER_WARNING("Invalid payload type with the session");
        return -1;
    }

    if (ntohs(header->cpart) >= ntohs(header->tlen)) {
        /* Never allow this case to happen */
        return -1;
    }

    bwc_feed_avg(session->bwc, length);

    if (ntohs(header->tlen) == length - sizeof (struct RTPHeader)) {
        /* The message is sent in single part */

        /* Only allow messages which have arrived in order;
         * drop late messages
         */
        if (chloss(session, header)) {
            return 0;
        } else {
            /* Message is not late; pick up the latest parameters */
            session->rsequnum = ntohs(header->sequnum);
            session->rtimestamp = ntohl(header->timestamp);
        }

        bwc_add_recv(session->bwc, length);

        /* Invoke processing of active multiparted message */
        if (session->mp) {
            if (session->mcb)
                session->mcb (session->cs, session->mp);
            else
                free(session->mp);

            session->mp = NULL;
        }

        /* The message came in the allowed time;
         * process it only if handler for the session is present.
         */

        if (!session->mcb)
            return 0;

        return session->mcb (session->cs, new_message(length, data, length));
    } else {
        /* The message is sent in multiple parts */

        if (session->mp) {
            /* There are 2 possible situations in this case:
             *      1) being that we got the part of already processing message.
             *      2) being that we got the part of a new/old message.
             *
             * We handle them differently as we only allow a single multiparted
             * processing message
             */

            if (session->mp->header.sequnum == ntohs(header->sequnum) &&
                    session->mp->header.timestamp == ntohl(header->timestamp)) {
                /* First case */

                /* Make sure we have enough allocated memory */
                if (session->mp->header.tlen - session->mp->len < length - sizeof(struct RTPHeader) ||
                        session->mp->header.tlen <= ntohs(header->cpart)) {
                    /* There happened to be some corruption on the stream;
                     * continue wihtout this part
                     */
                    return 0;
                }

                memcpy(session->mp->data + ntohs(header->cpart), data + sizeof(struct RTPHeader),
                       length - sizeof(struct RTPHeader));

                session->mp->len += length - sizeof(struct RTPHeader);

                bwc_add_recv(session->bwc, length);

                if (session->mp->len == session->mp->header.tlen) {
                    /* Received a full message; now push it for the further
                     * processing.
                     */
                    if (session->mcb)
                        session->mcb (session->cs, session->mp);
                    else
                        free(session->mp);

                    session->mp = NULL;
                }
            } else {
                /* Second case */

                if (session->mp->header.timestamp > ntohl(header->timestamp))
                    /* The received message part is from the old message;
                     * discard it.
                     */
                    return 0;

                /* Measure missing parts of the old message */
                bwc_add_lost(session->bwc,
                             (session->mp->header.tlen - session->mp->len) +

                             /* Must account sizes of rtp headers too */
                             ((session->mp->header.tlen - session->mp->len) /
                              MAX_CRYPTO_DATA_SIZE) * sizeof(struct RTPHeader) );

                /* Push the previous message for processing */
                if (session->mcb)
                    session->mcb (session->cs, session->mp);
                else
                    free(session->mp);

                session->mp = NULL;
                goto NEW_MULTIPARTED;
            }
        } else {
            /* In this case threat the message as if it was received in order
             */

            /* This is also a point for new multiparted messages */
NEW_MULTIPARTED:

            /* Only allow messages which have arrived in order;
             * drop late messages
             */
            if (chloss(session, header)) {
                return 0;
            } else {
                /* Message is not late; pick up the latest parameters */
                session->rsequnum = ntohs(header->sequnum);
                session->rtimestamp = ntohl(header->timestamp);
            }

            bwc_add_recv(session->bwc, length);

            /* Again, only store message if handler is present
             */
            if (session->mcb) {
                session->mp = new_message(ntohs(header->tlen) + sizeof(struct RTPHeader), data, length);

                /* Reposition data if necessary */
                if (ntohs(header->cpart));

                memmove(session->mp->data + ntohs(header->cpart), session->mp->data, session->mp->len);
            }
        }
    }

    return 0;
}
