/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EV_H
#define C_TOXCORE_TOXCORE_EV_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "net.h"  // For Socket

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Ev Ev;

/**
 * @brief Event types to monitor.
 */
typedef uint8_t Ev_Events;

#define EV_READ  (1 << 0)
#define EV_WRITE (1 << 1)
#define EV_ERROR (1 << 2)

/**
 * @brief Result of a triggered event.
 */
typedef struct Ev_Result {
    Socket sock;
    Ev_Events events;
    void *_Nullable data;
} Ev_Result;

/**
 * @brief Add a socket to the monitored set.
 *
 * This is called by `ev_add` to register a socket for event monitoring.
 *
 * @param self Backend-specific state.
 * @param sock The socket to monitor.
 * @param events Bitmask of events to monitor (EV_READ, EV_WRITE).
 * @param data User context pointer to be returned in Ev_Result.
 *
 * @return true on success, false if the socket is already registered or on error.
 */
typedef bool ev_add_cb(void *_Nullable self, Socket sock, Ev_Events events, void *_Nullable data);

/**
 * @brief Modify a registered socket's monitoring parameters.
 *
 * This is called by `ev_mod` to change the events or user data for a socket
 * that is already being monitored.
 *
 * @param self Backend-specific state.
 * @param sock The socket to modify.
 * @param events New bitmask of events to monitor.
 * @param data New user context pointer.
 *
 * @return true on success, false if the socket is not found or on error.
 */
typedef bool ev_mod_cb(void *_Nullable self, Socket sock, Ev_Events events, void *_Nullable data);

/**
 * @brief Remove a socket from the monitored set.
 *
 * This is called by `ev_del` to stop monitoring a socket.
 *
 * @param self Backend-specific state.
 * @param sock The socket to remove.
 *
 * @return true on success, false if the socket is not found.
 */
typedef bool ev_del_cb(void *_Nullable self, Socket sock);

/**
 * @brief Wait for events on registered sockets.
 *
 * This is called by `ev_run`. It blocks until at least one event occurs,
 * the timeout expires, or `ev_break` is called.
 *
 * @param self Backend-specific state.
 * @param results Array to be populated with triggered events.
 * @param max_results Maximum number of results to store in the array.
 * @param timeout_ms Maximum time to wait in milliseconds. 0 for non-blocking,
 *                   -1 for infinite wait.
 *
 * @return Number of events stored in `results`, 0 on timeout, or -1 on error.
 */
typedef int32_t ev_run_cb(void *_Nullable self, Ev_Result results[_Nonnull], uint32_t max_results, int32_t timeout_ms);

/** @brief Cleanup the event loop and free the Ev object. */
typedef void ev_kill_cb(Ev *_Nonnull ev);

/**
 * @brief Virtual function table for Ev.
 */
typedef struct Ev_Funcs {
    ev_add_cb *_Nonnull add_callback;
    ev_mod_cb *_Nonnull mod_callback;
    ev_del_cb *_Nonnull del_callback;
    ev_run_cb *_Nonnull run_callback;
    ev_kill_cb *_Nonnull kill_callback;
} Ev_Funcs;

/**
 * @brief The Event Loop object.
 */
struct Ev {
    const Ev_Funcs *_Nonnull funcs;
    void *_Nullable user_data;
};

/**
 * @brief Wrapper functions.
 */
bool ev_add(Ev *_Nonnull ev, Socket sock, Ev_Events events, void *_Nullable data);
bool ev_mod(Ev *_Nonnull ev, Socket sock, Ev_Events events, void *_Nullable data);
bool ev_del(Ev *_Nonnull ev, Socket sock);
int32_t ev_run(Ev *_Nonnull ev, Ev_Result results[_Nonnull], uint32_t max_results, int32_t timeout_ms);
void ev_kill(Ev *_Nullable ev);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_EV_H */
