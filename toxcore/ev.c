/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "ev.h"

#include <assert.h>

#include "ccompat.h"

bool ev_add(Ev *ev, Socket sock, Ev_Events events, void *data)
{
    assert(ev != nullptr);
    return ev->funcs->add_callback(ev->user_data, sock, events, data);
}

bool ev_mod(Ev *ev, Socket sock, Ev_Events events, void *data)
{
    assert(ev != nullptr);
    return ev->funcs->mod_callback(ev->user_data, sock, events, data);
}

bool ev_del(Ev *ev, Socket sock)
{
    assert(ev != nullptr);
    return ev->funcs->del_callback(ev->user_data, sock);
}

int32_t ev_run(Ev *ev, Ev_Result *results, uint32_t max_results, int32_t timeout_ms)
{
    assert(ev != nullptr);

    if (max_results == 0) {
        return 0;
    }

    return ev->funcs->run_callback(ev->user_data, results, max_results, timeout_ms);
}

void ev_kill(Ev *ev)
{
    if (ev == nullptr) {
        return;
    }

    ev->funcs->kill_callback(ev);
}
