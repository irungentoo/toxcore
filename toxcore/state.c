#include "state.h"

#include <string.h>

/* state load/save */
int state_load(const Logger *log, state_load_cb *state_load_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner)
{
    if (state_load_callback == nullptr || data == nullptr) {
        LOGGER_ERROR(log, "state_load() called with invalid args.\n");
        return -1;
    }


    const uint32_t size_head = sizeof(uint32_t) * 2;

    while (length >= size_head) {
        uint32_t length_sub;
        lendian_to_host32(&length_sub, data);

        uint32_t cookie_type;
        lendian_to_host32(&cookie_type, data + sizeof(uint32_t));

        data += size_head;
        length -= size_head;

        if (length < length_sub) {
            /* file truncated */
            LOGGER_ERROR(log, "state file too short: %u < %u\n", length, length_sub);
            return -1;
        }

        if (lendian_to_host16((cookie_type >> 16)) != cookie_inner) {
            /* something is not matching up in a bad way, give up */
            LOGGER_ERROR(log, "state file garbled: %04x != %04x\n", cookie_type >> 16, cookie_inner);
            return -1;
        }

        const uint16_t type = lendian_to_host16(cookie_type & 0xFFFF);

        switch (state_load_callback(outer, data, length_sub, type)) {
            case STATE_LOAD_STATUS_CONTINUE:
                data += length_sub;
                length -= length_sub;
                break;

            case STATE_LOAD_STATUS_ERROR:
                return -1;

            case STATE_LOAD_STATUS_END:
                return 0;
        }
    }

    if (length != 0) {
        LOGGER_ERROR(log, "unparsed data in state file of length %u\n", length);
        return -1;
    }

    return 0;
}

uint16_t lendian_to_host16(uint16_t lendian)
{
#ifdef WORDS_BIGENDIAN
    return (lendian << 8) | (lendian >> 8);
#else
    return lendian;
#endif
}

void host_to_lendian32(uint8_t *dest,  uint32_t num)
{
#ifdef WORDS_BIGENDIAN
    num = ((num << 8) & 0xFF00FF00) | ((num >> 8) & 0xFF00FF);
    num = (num << 16) | (num >> 16);
#endif
    memcpy(dest, &num, sizeof(uint32_t));
}

void lendian_to_host32(uint32_t *dest, const uint8_t *lendian)
{
    uint32_t d;
    memcpy(&d, lendian, sizeof(uint32_t));
#ifdef WORDS_BIGENDIAN
    d = ((d << 8) & 0xFF00FF00) | ((d >> 8) & 0xFF00FF);
    d = (d << 16) | (d >> 16);
#endif
    *dest = d;
}
