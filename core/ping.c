/*
 * ping.c -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>
#include <stdint.h>

#include "network.h"
#include "util.h"

#define PING_NUM_MAX 256
#define PING_TIMEOUT 5 // 5s

typedef struct {
    tox_IP_Port  ipp;
    uint64_t id;
    uint64_t timestamp;
} pinged_t;

static pinged_t pings[PING_NUM_MAX];
static size_t   num_pings;
static size_t   pos_pings;


void init_ping()
{
    num_pings = 0;
    pos_pings = 0;
}

static bool is_timeout(uint64_t time)
{
    return (time + PING_TIMEOUT) < now();
}

static void remove_timeouts()   // O(n)
{
    size_t i, id;
    size_t new_pos = pos_pings;
    size_t new_num = num_pings;

    // Loop through buffer, oldest first
    for (i=0; i<num_pings; i++) {
        id = (pos_pings + i) % PING_NUM_MAX;

        if(is_timeout(pings[id].timestamp)) {
            new_pos++;
            new_num--;
        }
        // Break here because list is sorted.
        else
            break;
    }

    num_pings = new_num;
    pos_pings = new_pos % PING_NUM_MAX;
}

uint64_t add_ping(tox_IP_Port ipp)   // O(n)
{
    size_t p;

    remove_timeouts();

    // Remove oldest ping if full buffer
    if (num_pings == PING_NUM_MAX) {
        num_pings--;
        pos_pings = (pos_pings + 1) % PING_NUM_MAX;
    }

    // Insert new ping at end of list
    p = (pos_pings + num_pings) % PING_NUM_MAX;

    pings[p].ipp       = ipp;
    pings[p].timestamp = now();
    pings[p].id        = random_64b();

    num_pings++;
    return pings[p].id;
}

bool is_pinging(tox_IP_Port ipp, uint64_t ping_id)   // O(n) TODO: replace this with something else.
{
    if (ipp.ip.i == 0 && ping_id == 0)
        return false;
    
    size_t i, id;

    remove_timeouts();

    for (i=0; i<num_pings; i++) {
        id = (pos_pings + i) % PING_NUM_MAX;

        if ((ipp_eq(pings[id].ipp, ipp) || ipp.ip.i == 0) && (pings[id].id == ping_id || ping_id == 0)) {
            return true;
        }
    }

    return false;
}
