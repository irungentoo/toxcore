/**  bwcontroller.c
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

#include <assert.h>
#include "bwcontroller.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#define BWC_PACKET_ID 196
#define BWC_SEND_INTERVAL_MS 1000
#define BWC_REFRESH_INTERVAL_MS 10000
#define BWC_AVG_PKT_COUNT 20

/**
 *
 */

struct BWController_s {
    void (*mcb) (BWController *, uint32_t, float, void *);
    void *mcb_data;

    Messenger *m;
    uint32_t friend_number;

    struct {
        uint32_t lru; /* Last recv update time stamp */
        uint32_t lsu; /* Last sent update time stamp */
        uint32_t lfu; /* Last refresh time stamp */

        uint32_t lost;
        uint32_t recv;
    } cycle;

    struct {
        uint32_t rb_s[BWC_AVG_PKT_COUNT];
        RingBuffer *rb;
    } rcvpkt; /* To calculate average received packet */
};

int bwc_handle_data(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object);
void send_update(BWController *bwc);

BWController *bwc_new(Messenger *m, uint32_t friendnumber,
                      void (*mcb) (BWController *, uint32_t, float, void *),
                      void *udata)
{
    BWController *retu = calloc(sizeof(struct BWController_s), 1);

    retu->mcb = mcb;
    retu->mcb_data = udata;
    retu->m = m;
    retu->friend_number = friendnumber;
    retu->cycle.lsu = retu->cycle.lfu = current_time_monotonic();
    retu->rcvpkt.rb = rb_new(BWC_AVG_PKT_COUNT);

    /* Fill with zeros */
    int i = 0;

    for (; i < BWC_AVG_PKT_COUNT; i ++)
        rb_write(retu->rcvpkt.rb, retu->rcvpkt.rb_s + i);

    m_callback_rtp_packet(m, friendnumber, BWC_PACKET_ID, bwc_handle_data, retu);

    return retu;
}
void bwc_kill(BWController *bwc)
{
    if (!bwc)
        return;

    m_callback_rtp_packet(bwc->m, bwc->friend_number, BWC_PACKET_ID, NULL, NULL);

    rb_kill(bwc->rcvpkt.rb);
    free(bwc);
}
void bwc_feed_avg(BWController *bwc, uint32_t bytes)
{
    uint32_t *p;

    rb_read(bwc->rcvpkt.rb, (void **) &p);
    rb_write(bwc->rcvpkt.rb, p);

    *p = bytes;
}
void bwc_add_lost(BWController *bwc, uint32_t bytes)
{
    if (!bwc)
        return;

    if (!bytes) {
        uint32_t *t_avg[BWC_AVG_PKT_COUNT], c = 1;

        rb_data(bwc->rcvpkt.rb, (void **) t_avg);

        int i = 0;

        for (; i < BWC_AVG_PKT_COUNT; i ++) {
            bytes += *(t_avg[i]);

            if (*(t_avg[i]))
                c++;
        }

        bytes /= c;
    }

    bwc->cycle.lost += bytes;
    send_update(bwc);
}
void bwc_add_recv(BWController *bwc, uint32_t bytes)
{
    if (!bwc || !bytes)
        return;

    bwc->cycle.recv += bytes;
    send_update(bwc);
}


struct BWCMessage {
    uint32_t lost;
    uint32_t recv;
};

void send_update(BWController *bwc)
{
    if (current_time_monotonic() - bwc->cycle.lfu > BWC_REFRESH_INTERVAL_MS) {

        bwc->cycle.lost /= 10;
        bwc->cycle.recv /= 10;
        bwc->cycle.lfu = current_time_monotonic();
    } else if (current_time_monotonic() - bwc->cycle.lsu > BWC_SEND_INTERVAL_MS) {

        if (bwc->cycle.lost) {
            LOGGER_DEBUG ("%p Sent update rcv: %u lost: %u",
                          bwc, bwc->cycle.recv, bwc->cycle.lost);

            uint8_t p_msg[sizeof(struct BWCMessage) + 1];
            struct BWCMessage *b_msg = (struct BWCMessage *)(p_msg + 1);

            p_msg[0] = BWC_PACKET_ID;
            b_msg->lost = htonl(bwc->cycle.lost);
            b_msg->recv = htonl(bwc->cycle.recv);

            if (-1 == send_custom_lossy_packet(bwc->m, bwc->friend_number, p_msg, sizeof(p_msg)))
                LOGGER_WARNING("BWC send failed (len: %d)! std error: %s", sizeof(p_msg), strerror(errno));
        }

        bwc->cycle.lsu = current_time_monotonic();
    }
}
int on_update (BWController *bwc, struct BWCMessage *msg)
{
    LOGGER_DEBUG ("%p Got update from peer", bwc);

    /* Peer must respect time boundary */
    if (current_time_monotonic() < bwc->cycle.lru + BWC_SEND_INTERVAL_MS) {
        LOGGER_DEBUG("%p Rejecting extra update", bwc);
        return -1;
    }

    bwc->cycle.lru = current_time_monotonic();

    msg->recv = ntohl(msg->recv);
    msg->lost = ntohl(msg->lost);

    LOGGER_DEBUG ("recved: %u lost: %u", msg->recv, msg->lost);

    if (msg->lost && bwc->mcb)
        bwc->mcb(bwc, bwc->friend_number,
                 ((float) (msg->lost) / (msg->recv + msg->lost)),
                 bwc->mcb_data);

    return 0;
}
int bwc_handle_data(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
{
    if (length - 1 != sizeof(struct BWCMessage))
        return -1;

    /* NOTE the data is mutable */
    return on_update(object, (struct BWCMessage *) (data + 1));
}
