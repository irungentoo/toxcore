/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#include "state.h"

#include <string.h>

#include "ccompat.h"

/** state load/save */
int state_load(const Logger *log, state_load_cb *state_load_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (state_load_callback == nullptr || data == nullptr) {
        LOGGER_ERROR(log, "state_load() called with invalid args.");
        return -1;
    }


    const uint32_t size_head = sizeof(uint32_t) * 2;

    while (length >= size_head) {
        uint32_t length_sub;
        lendian_bytes_to_host32(&length_sub, data);

        uint32_t cookie_type;
        lendian_bytes_to_host32(&cookie_type, data + sizeof(uint32_t));

        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
            LOGGER_ERROR(log, "state file too short: %u < %u", length, length_sub);
            return -1;
        }

        if (lendian_to_host16(cookie_type >> 16) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
            LOGGER_ERROR(log, "state file garbled: %04x != %04x", cookie_type >> 16, cookie_inner);
            return -1;
        }

        const uint16_t type = lendian_to_host16(cookie_type & 0xFFFF);

        switch (state_load_callback(outer, data, length_sub, type)) {
            case STATE_LOAD_STATUS_CONTINUE: {
                data += length_sub;
                length -= length_sub;
                break;
            }

            case STATE_LOAD_STATUS_ERROR: {
                LOGGER_ERROR(log, "Error occcured in state file (type: %u).", type);
                return -1;
            }

            case STATE_LOAD_STATUS_END: {
                return 0;
            }
        }
    }

    if (length != 0) {
        LOGGER_ERROR(log, "unparsed data in state file of length %u", length);
        return -1;
    }

    return 0;
}

uint8_t *state_write_section_header(uint8_t *data, uint16_t cookie_type, uint32_t len, uint32_t section_type)
{
    host_to_lendian_bytes32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian_bytes32(data, (host_to_lendian16(cookie_type) << 16) | host_to_lendian16(section_type));
    data += sizeof(uint32_t);
    return data;
}

uint16_t lendian_to_host16(uint16_t lendian)
{
#ifdef WORDS_BIGENDIAN
    return (lendian << 8) | (lendian >> 8);
#else
    return lendian;
#endif
}

uint16_t host_to_lendian16(uint16_t host)
{
    return lendian_to_host16(host);
}

void host_to_lendian_bytes64(uint8_t *dest, uint64_t num)
{
#ifdef WORDS_BIGENDIAN
    num = ((num << 8) & 0xFF00FF00FF00FF00) | ((num >> 8) & 0xFF00FF00FF00FF);
    num = ((num << 16) & 0xFFFF0000FFFF0000) | ((num >> 16) & 0xFFFF0000FFFF);
    num = (num << 32) | (num >> 32);
#endif
    memcpy(dest, &num, sizeof(uint64_t));
}

void lendian_bytes_to_host64(uint64_t *dest, const uint8_t *lendian)
{
    uint64_t d;
    memcpy(&d, lendian, sizeof(uint64_t));
#ifdef WORDS_BIGENDIAN
    d = ((d << 8) & 0xFF00FF00FF00FF00) | ((d >> 8) & 0xFF00FF00FF00FF);
    d = ((d << 16) & 0xFFFF0000FFFF0000) | ((d >> 16) & 0xFFFF0000FFFF);
    d = (d << 32) | (d >> 32);
#endif
    *dest = d;
}

void host_to_lendian_bytes32(uint8_t *dest, uint32_t num)
{
#ifdef WORDS_BIGENDIAN
    num = ((num << 8) & 0xFF00FF00) | ((num >> 8) & 0xFF00FF);
    num = (num << 16) | (num >> 16);
#endif
    memcpy(dest, &num, sizeof(uint32_t));
}

void lendian_bytes_to_host32(uint32_t *dest, const uint8_t *lendian)
{
    uint32_t d;
    memcpy(&d, lendian, sizeof(uint32_t));
#ifdef WORDS_BIGENDIAN
    d = ((d << 8) & 0xFF00FF00) | ((d >> 8) & 0xFF00FF);
    d = (d << 16) | (d >> 16);
#endif
    *dest = d;
}

void host_to_lendian_bytes16(uint8_t *dest, uint16_t num)
{
#ifdef WORDS_BIGENDIAN
    num = (num << 8) | (num >> 8);
#endif
    memcpy(dest, &num, sizeof(uint16_t));
}

void lendian_bytes_to_host16(uint16_t *dest, const uint8_t *lendian)
{
    uint16_t d;
    memcpy(&d, lendian, sizeof(uint16_t));
#ifdef WORDS_BIGENDIAN
    d = (d << 8) | (d >> 8);
#endif
    *dest = d;
}
