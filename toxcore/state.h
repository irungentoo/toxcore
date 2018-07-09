/**
 * The state module is responsible for parsing the Tox save data format and for
 * saving state in that format.
 *
 * This module provides functions for iterating over serialised data sections
 * and reading/writing numbers in the correct format (little endian).
 *
 * Note that unlike the Tox network protocol, the save data stores its values in
 * little endian, which is native to most desktop and server architectures in
 * 2018.
 */
#ifndef C_TOXCORE_TOXCORE_STATE_H
#define C_TOXCORE_TOXCORE_STATE_H

#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

// Returned by the state_load_cb to instruct the loader on what to do next.
typedef enum State_Load_Status {
    // Continue loading state data sections.
    STATE_LOAD_STATUS_CONTINUE,
    // An error occurred. Stop loading sections.
    STATE_LOAD_STATUS_ERROR,
    // We're at the end of the save data, terminate loading successfully.
    STATE_LOAD_STATUS_END,
} State_Load_Status;

typedef State_Load_Status state_load_cb(void *outer, const uint8_t *data, uint32_t len, uint16_t type);

// state load/save
int state_load(const Logger *log, state_load_cb *state_load_callback, void *outer,
               const uint8_t *data, uint32_t length, uint16_t cookie_inner);

// Utilities for state data serialisation.

uint16_t lendian_to_host16(uint16_t lendian);
#define host_tolendian16(x) lendian_to_host16(x)

void host_to_lendian32(uint8_t *dest, uint32_t num);
void lendian_to_host32(uint32_t *dest, const uint8_t *lendian);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_STATE_H
