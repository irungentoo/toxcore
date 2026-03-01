#include "framework.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>

#include "../../../testing/misc_tools.h"
#include "../../../toxcore/tox_struct.h"
#include "../../../toxcore/network.h"

#define MAX_NODES 128

typedef struct {
    Tox_Connection connection_status;
    bool finished;
    bool offline;
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    uint8_t dht_id[TOX_PUBLIC_KEY_SIZE];
    uint8_t address[TOX_ADDRESS_SIZE];
    uint16_t udp_port;
} ToxNodeMirror;

struct ToxNode {
    Tox *tox;
    Tox_Options *options;
    Tox_Dispatch *dispatch;
    uint32_t index;
    char *alias;

    ToxScenario *scenario;
    pthread_t thread;
    tox_node_script_cb *script;
    void *script_ctx;
    size_t script_ctx_size;

    void *mirrored_ctx;
    void *mirrored_ctx_public;
    ToxNodeMirror mirror;
    ToxNodeMirror mirror_public;

    bool finished;
    bool offline;
    uint32_t barrier_index;
    uint64_t last_tick;
    bool seen_events[256];
};

struct ToxScenario {
    ToxNode *nodes[MAX_NODES];
    uint32_t num_nodes;
    uint32_t num_active;
    uint32_t num_ready;

    uint64_t virtual_clock;
    uint64_t timeout_ms;
    uint64_t tick_count;

    pthread_mutex_t mutex;
    pthread_mutex_t clock_mutex;
    pthread_cond_t cond_runner;
    pthread_cond_t cond_nodes;

    bool run_started;

    bool trace_enabled;
    bool event_log_enabled;

    struct {
        const char *name;
        uint32_t count;
    } barrier;
};

static uint64_t get_scenario_clock(void *user_data)
{
    ToxScenario *s = (ToxScenario *)user_data;
    pthread_mutex_lock(&s->clock_mutex);
    uint64_t time = s->virtual_clock;
    pthread_mutex_unlock(&s->clock_mutex);
    return time;
}

static void framework_debug_log(Tox *tox, Tox_Log_Level level, const char *file, uint32_t line,
                                const char *func, const char *message, void *user_data)
{
    ToxNode *node = (ToxNode *)user_data;
    ck_assert(node != nullptr);

    if (level == TOX_LOG_LEVEL_TRACE) {
        if (node == nullptr || !node->scenario->trace_enabled) {
            return;
        }
    }

    const char *level_name = "UNKNOWN";
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            level_name = "TRACE";
            break;
        case TOX_LOG_LEVEL_DEBUG:
            level_name = "DEBUG";
            break;
        case TOX_LOG_LEVEL_INFO:
            level_name = "INFO";
            break;
        case TOX_LOG_LEVEL_WARNING:
            level_name = "WARN";
            break;
        case TOX_LOG_LEVEL_ERROR:
            level_name = "ERROR";
            break;
    }

    const uint64_t relative_time = node ? (get_scenario_clock(node->scenario) - 1000) : 0;
    fprintf(stderr, "[%08lu] [%s] %s %s:%u %s: %s\n", (unsigned long)relative_time,
            node != nullptr ? node->alias : "Unknown", level_name, file, line, func, message);
}

void tox_node_log(ToxNode *node, const char *format, ...)
{
    ck_assert(node != nullptr);
    va_list args;
    va_start(args, format);
    uint64_t relative_time = get_scenario_clock(node->scenario) - 1000;
    fprintf(stderr, "[%08lu] [%s] ", (unsigned long)relative_time, node->alias ? node->alias : "Unknown");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void tox_scenario_log(const ToxScenario *s, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    uint64_t relative_time = get_scenario_clock((void *)(uintptr_t)s) - 1000;
    fprintf(stderr, "[%08lu] [Runner] ", (unsigned long)relative_time);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

ToxScenario *tox_scenario_new(int argc, char *const argv[], uint64_t timeout_ms)
{
    static bool seeded = false;
    if (!seeded) {
        srand(time(nullptr));
        seeded = true;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--wait-time") == 0 && i + 1 < argc) {
            timeout_ms = (uint64_t)atoll(argv[i + 1]) * 1000;
            break;
        }
    }

    ToxScenario *s = (ToxScenario *)calloc(1, sizeof(ToxScenario));
    ck_assert(s != nullptr);

    pthread_mutex_init(&s->mutex, nullptr);
    pthread_mutex_init(&s->clock_mutex, nullptr);
    pthread_cond_init(&s->cond_runner, nullptr);
    pthread_cond_init(&s->cond_nodes, nullptr);

    s->timeout_ms = timeout_ms;
    s->virtual_clock = 1000;
    s->trace_enabled = (getenv("TOX_TRACE") != nullptr);
    s->event_log_enabled = (getenv("TOX_EVENT_LOG") != nullptr);
    return s;
}

void tox_scenario_free(ToxScenario *s)
{
    for (uint32_t i = 0; i < s->num_nodes; ++i) {
        ToxNode *node = s->nodes[i];
        ck_assert(node != nullptr);
        tox_dispatch_free(node->dispatch);
        tox_kill(node->tox);
        tox_options_free(node->options);
        free(node->alias);
        free(node->mirrored_ctx);
        free(node->mirrored_ctx_public);
        free(node);
    }
    pthread_mutex_destroy(&s->mutex);
    pthread_mutex_destroy(&s->clock_mutex);
    pthread_cond_destroy(&s->cond_runner);
    pthread_cond_destroy(&s->cond_nodes);
    free(s);
}

Tox *tox_node_get_tox(const ToxNode *node)
{
    ck_assert(node != nullptr);
    ToxScenario *s = node->scenario;
    pthread_mutex_lock(&s->mutex);
    Tox *tox = node->tox;
    pthread_mutex_unlock(&s->mutex);
    return tox;
}

void tox_node_get_address(const ToxNode *node, uint8_t *address)
{
    ck_assert(node != nullptr);
    ck_assert(address != nullptr);
    memcpy(address, node->mirror_public.address, TOX_ADDRESS_SIZE);
}

ToxScenario *tox_node_get_scenario(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->scenario;
}

Tox_Connection tox_node_get_connection_status(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->mirror_public.connection_status;
}

Tox_Connection tox_node_get_friend_connection_status(const ToxNode *node, uint32_t friend_number)
{
    ck_assert(node != nullptr);
    // Note: Friend status is not currently mirrored.
    // This is safe if called by the node on itself.
    // If called on a peer, it might still race.
    Tox_Err_Friend_Query err;
    Tox_Connection conn = tox_friend_get_connection_status(node->tox, friend_number, &err);
    if (err != TOX_ERR_FRIEND_QUERY_OK) {
        return TOX_CONNECTION_NONE;
    }
    return conn;
}

bool tox_node_is_self_connected(const ToxNode *node)
{
    return tox_node_get_connection_status(node) != TOX_CONNECTION_NONE;
}

bool tox_node_is_friend_connected(const ToxNode *node, uint32_t friend_number)
{
    return tox_node_get_friend_connection_status(node, friend_number) != TOX_CONNECTION_NONE;
}

uint32_t tox_node_get_conference_peer_count(const ToxNode *node, uint32_t conference_number)
{
    ck_assert(node != nullptr);
    Tox_Err_Conference_Peer_Query err;
    uint32_t count = tox_conference_peer_count(node->tox, conference_number, &err);
    if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        return 0;
    }
    return count;
}

void tox_node_set_offline(ToxNode *node, bool offline)
{
    ck_assert(node != nullptr);
    node->offline = offline;
}

bool tox_node_is_offline(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->mirror_public.offline;
}

bool tox_node_is_finished(const ToxNode *node)
{
    ck_assert(node != nullptr);
    ToxScenario *s = node->scenario;
    pthread_mutex_lock(&s->mutex);
    bool finished = node->mirror_public.finished;
    pthread_mutex_unlock(&s->mutex);
    return finished;
}

bool tox_scenario_is_running(ToxNode *self)
{
    bool running;
    pthread_mutex_lock(&self->scenario->mutex);
    running = self->scenario->run_started;
    pthread_mutex_unlock(&self->scenario->mutex);
    return running;
}

bool tox_node_friend_name_is(const ToxNode *node, uint32_t friend_number, const uint8_t *name, size_t length)
{
    ck_assert(node != nullptr);
    Tox_Err_Friend_Query err;
    size_t actual_len = tox_friend_get_name_size(node->tox, friend_number, &err);
    if (err != TOX_ERR_FRIEND_QUERY_OK || actual_len != length) {
        return false;
    }
    uint8_t *actual_name = (uint8_t *)malloc(length);
    ck_assert(actual_name != nullptr);
    tox_friend_get_name(node->tox, friend_number, actual_name, nullptr);
    bool match = (memcmp(actual_name, name, length) == 0);
    free(actual_name);
    return match;
}

bool tox_node_friend_status_message_is(const ToxNode *node, uint32_t friend_number, const uint8_t *msg, size_t length)
{
    ck_assert(node != nullptr);
    Tox_Err_Friend_Query err;
    size_t actual_len = tox_friend_get_status_message_size(node->tox, friend_number, &err);
    if (err != TOX_ERR_FRIEND_QUERY_OK || actual_len != length) {
        return false;
    }
    uint8_t *actual_msg = (uint8_t *)malloc(length);
    ck_assert(actual_msg != nullptr);
    tox_friend_get_status_message(node->tox, friend_number, actual_msg, nullptr);
    bool match = (memcmp(actual_msg, msg, length) == 0);
    free(actual_msg);
    return match;
}

bool tox_node_friend_typing_is(const ToxNode *node, uint32_t friend_number, bool is_typing)
{
    ck_assert(node != nullptr);
    Tox_Err_Friend_Query err;
    bool actual = tox_friend_get_typing(node->tox, friend_number, &err);
    return (err == TOX_ERR_FRIEND_QUERY_OK && actual == is_typing);
}

void tox_scenario_yield(ToxNode *self)
{
    // 1. Poll Tox (Strictly in the node's thread), only if not offline
    if (!tox_node_is_offline(self)) {
        Tox_Err_Events_Iterate ev_err;
        Tox_Events *events = tox_events_iterate(self->tox, nullptr, &ev_err);
        if (events != nullptr) {
            uint32_t size = tox_events_get_size(events);
            for (uint32_t j = 0; j < size; ++j) {
                const Tox_Event *ev = tox_events_get(events, j);
                const Tox_Event_Type type = tox_event_get_type(ev);
                self->seen_events[type] = true;
                if (self->scenario->event_log_enabled) {
                    tox_node_log(self, "Received event: %s (%u)", tox_event_type_to_string(type), type);
                }
            }
            tox_dispatch_invoke(self->dispatch, events, self);
            tox_events_free(events);
        }
    }

    ToxScenario *s = self->scenario;

    // 2. Update mirror (Outside lock to reduce contention)
    self->mirror.connection_status = tox_self_get_connection_status(self->tox);
    self->mirror.offline = self->offline;
    tox_self_get_public_key(self->tox, self->mirror.public_key);
    tox_self_get_dht_id(self->tox, self->mirror.dht_id);
    tox_self_get_address(self->tox, self->mirror.address);
    Tox_Err_Get_Port port_err;
    self->mirror.udp_port = tox_self_get_udp_port(self->tox, &port_err);

    if (self->mirrored_ctx != nullptr && self->script_ctx != nullptr) {
        memcpy(self->mirrored_ctx, self->script_ctx, self->script_ctx_size);
    }

    pthread_mutex_lock(&s->mutex);

    self->mirror.finished = self->finished;
    self->last_tick = s->tick_count;
    s->num_ready++;

    // Wake runner
    pthread_cond_signal(&s->cond_runner);

    // Wait for next tick
    while (self->last_tick == s->tick_count && s->run_started) {
        pthread_cond_wait(&s->cond_nodes, &s->mutex);
    }

    pthread_mutex_unlock(&s->mutex);

    // Give the OS a chance to deliver UDP packets
    c_sleep(1);
}

void tox_scenario_wait_for_event(ToxNode *self, Tox_Event_Type type)
{
    while (!self->seen_events[type] && tox_scenario_is_running(self)) {
        tox_scenario_yield(self);
    }
}

void tox_scenario_barrier_wait(ToxNode *self)
{
    ToxScenario *s = self->scenario;
    pthread_mutex_lock(&s->mutex);
    uint32_t my_barrier_index = ++self->barrier_index;
    pthread_mutex_unlock(&s->mutex);

    while (tox_scenario_is_running(self)) {
        // Even if all nodes have reached the barrier, we MUST yield at least once
        // to ensure the runner has a chance to synchronize the snapshots for this barrier.
        tox_scenario_yield(self);

        pthread_mutex_lock(&s->mutex);
        uint32_t reached = 0;
        for (uint32_t i = 0; i < s->num_nodes; ++i) {
            if (s->nodes[i]->barrier_index >= my_barrier_index || s->nodes[i]->finished) {
                reached++;
            }
        }
        const bool done = reached >= s->num_nodes;
        pthread_mutex_unlock(&s->mutex);

        if (done) {
            break;
        }
    }
}

void tox_node_wait_for_self_connected(ToxNode *self)
{
    WAIT_UNTIL(tox_node_is_self_connected(self));
}

void tox_node_wait_for_friend_connected(ToxNode *self, uint32_t friend_number)
{
    WAIT_UNTIL(tox_node_is_friend_connected(self, friend_number));
}

static void *node_thread_wrapper(void *arg)
{
    ToxNode *node = (ToxNode *)arg;
    ck_assert(node != nullptr);
    ToxScenario *s = node->scenario;

    // Wait for the starting signal from runner
    pthread_mutex_lock(&s->mutex);
    s->num_ready++;
    pthread_cond_signal(&s->cond_runner);
    while (s->tick_count == 0 && s->run_started) {
        pthread_cond_wait(&s->cond_nodes, &s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);

    // Run the actual script
    srand(time(nullptr) + node->index);
    node->script(node, node->script_ctx);

    // After the script is done, keep polling until the scenario is over
    pthread_mutex_lock(&s->mutex);
    node->finished = true;
    s->num_active--;
    uint32_t active = s->num_active;
    pthread_mutex_unlock(&s->mutex);

    tox_node_log(node, "finished script, active nodes remaining: %u", active);

    pthread_mutex_lock(&s->mutex);
    pthread_cond_signal(&s->cond_runner);

    while (s->run_started) {
        uint64_t tick_at_start = s->tick_count;
        s->num_ready++;
        pthread_cond_signal(&s->cond_runner);

        while (tick_at_start == s->tick_count && s->run_started) {
            pthread_cond_wait(&s->cond_nodes, &s->mutex);
        }
        pthread_mutex_unlock(&s->mutex);

        // 2. Update mirror outside lock
        node->mirror.connection_status = tox_self_get_connection_status(node->tox);
        node->mirror.finished = node->finished;
        node->mirror.offline = node->offline;

        if (node->mirrored_ctx != nullptr && node->script_ctx != nullptr) {
            memcpy(node->mirrored_ctx, node->script_ctx, node->script_ctx_size);
        }

        // Poll Tox even when script is "finished"
        Tox_Err_Events_Iterate ev_err;
        Tox_Events *events = tox_events_iterate(node->tox, nullptr, &ev_err);
        if (events != nullptr) {
            tox_dispatch_invoke(node->dispatch, events, node);
            tox_events_free(events);
        }
        pthread_mutex_lock(&s->mutex);
    }
    pthread_mutex_unlock(&s->mutex);

    return nullptr;
}

static Tox *create_tox_with_port_retry(Tox_Options *opts, void *log_user_data, Tox_Err_New *out_err)
{
    tox_options_set_log_user_data(opts, log_user_data);

    if (tox_options_get_start_port(opts) == 0 && tox_options_get_end_port(opts) == 0) {
        tox_options_set_start_port(opts, TOX_PORT_DEFAULT);
        tox_options_set_end_port(opts, 65535);
    }

    uint16_t tcp_port = tox_options_get_tcp_port(opts);
    Tox *tox = nullptr;

    for (int i = 0; i < 50; ++i) {
        tox = tox_new(opts, out_err);

        if (*out_err != TOX_ERR_NEW_PORT_ALLOC || tcp_port == 0) {
            break;
        }

        tcp_port++;
        tox_options_set_tcp_port(opts, tcp_port);
    }

    return tox;
}

ToxNode *tox_scenario_add_node_ex(ToxScenario *s, const char *alias, tox_node_script_cb *script, void *ctx, size_t ctx_size, const Tox_Options *options)
{
    if (s->num_nodes >= MAX_NODES) {
        return nullptr;
    }

    ToxNode *node = (ToxNode *)calloc(1, sizeof(ToxNode));
    ck_assert(node != nullptr);
    if (alias != nullptr) {
        size_t len = strlen(alias) + 1;
        node->alias = (char *)malloc(len);
        ck_assert(node->alias != nullptr);
        memcpy(node->alias, alias, len);
    }
    node->index = s->num_nodes;
    node->scenario = s;
    node->script = script;
    node->script_ctx = ctx;
    node->script_ctx_size = ctx_size;

    if (ctx_size > 0) {
        node->mirrored_ctx = calloc(1, ctx_size);
        ck_assert(node->mirrored_ctx != nullptr);
        node->mirrored_ctx_public = calloc(1, ctx_size);
        ck_assert(node->mirrored_ctx_public != nullptr);
        if (ctx != nullptr) {
            memcpy(node->mirrored_ctx, ctx, ctx_size);
            memcpy(node->mirrored_ctx_public, ctx, ctx_size);
        }
    }

    Tox_Options *opts = tox_options_new(nullptr);
    if (options != nullptr) {
        tox_options_copy(opts, options);
    } else {
        tox_options_set_ipv6_enabled(opts, false);
        tox_options_set_local_discovery_enabled(opts, false);
    }

    tox_options_set_log_callback(opts, framework_debug_log);
    Tox_Err_New err;
    node->tox = create_tox_with_port_retry(opts, node, &err);

    if (err == TOX_ERR_NEW_OK) {
        ck_assert(node->tox != nullptr);
        node->options = tox_options_new(nullptr);
        tox_options_copy(node->options, opts);
    }

    tox_options_free(opts);


    if (err != TOX_ERR_NEW_OK) {
        tox_scenario_log(s, "Failed to create Tox instance for node %s: %u", alias, err);
        free(node);
        return nullptr;
    }

    node->dispatch = tox_dispatch_new(nullptr);
    tox_events_init(node->tox);
    mono_time_set_current_time_callback(node->tox->mono_time, get_scenario_clock, s);

    // Initial mirror population
    node->mirror.connection_status = tox_self_get_connection_status(node->tox);
    tox_self_get_public_key(node->tox, node->mirror.public_key);
    tox_self_get_dht_id(node->tox, node->mirror.dht_id);
    tox_self_get_address(node->tox, node->mirror.address);
    Tox_Err_Get_Port port_err;
    node->mirror.udp_port = tox_self_get_udp_port(node->tox, &port_err);

    node->mirror_public = node->mirror;

    s->nodes[s->num_nodes++] = node;
    return node;
}

ToxNode *tox_scenario_add_node(ToxScenario *s, const char *alias, tox_node_script_cb *script, void *ctx, size_t ctx_size)
{
    return tox_scenario_add_node_ex(s, alias, script, ctx, ctx_size, nullptr);
}

ToxNode *tox_scenario_get_node(ToxScenario *s, uint32_t index)
{
    if (index >= s->num_nodes) {
        return nullptr;
    }
    return s->nodes[index];
}

const char *tox_node_get_alias(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->alias;
}

uint32_t tox_node_get_index(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->index;
}

void *tox_node_get_script_ctx(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->script_ctx;
}

const void *tox_node_get_peer_ctx(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->mirrored_ctx_public;
}

Tox_Dispatch *tox_node_get_dispatch(const ToxNode *node)
{
    ck_assert(node != nullptr);
    return node->dispatch;
}

uint64_t tox_scenario_get_time(ToxScenario *s)
{
    pthread_mutex_lock(&s->clock_mutex);
    uint64_t time = s->virtual_clock;
    pthread_mutex_unlock(&s->clock_mutex);
    return time;
}

ToxScenarioStatus tox_scenario_run(ToxScenario *s)
{
    pthread_mutex_lock(&s->mutex);
    s->num_active = s->num_nodes;
    s->num_ready = 0;
    s->tick_count = 0;
    s->run_started = true;
    pthread_mutex_unlock(&s->mutex);

    // Start all node threads
    for (uint32_t i = 0; i < s->num_nodes; ++i) {
        pthread_create(&s->nodes[i]->thread, nullptr, node_thread_wrapper, s->nodes[i]);
    }

    pthread_mutex_lock(&s->mutex);

    uint64_t start_clock = tox_scenario_get_time(s);
    uint64_t deadline = start_clock + s->timeout_ms;

    while (s->num_active > 0 && tox_scenario_get_time(s) < deadline) {
        // 1. Wait until all nodes (including finished ones) have reached the barrier
        while (s->num_ready < s->num_nodes) {
            pthread_cond_wait(&s->cond_runner, &s->mutex);
        }

        // 2. Synchronize Snapshots
        for (uint32_t i = 0; i < s->num_nodes; ++i) {
            ToxNode *node = s->nodes[i];
            ck_assert(node != nullptr);
            node->mirror_public = node->mirror;
            if (node->mirrored_ctx_public && node->mirrored_ctx) {
                memcpy(node->mirrored_ctx_public, node->mirrored_ctx, node->script_ctx_size);
            }
        }

        // 3. Advance tick and clock
        s->num_ready = 0;
        s->tick_count++;
        pthread_mutex_lock(&s->clock_mutex);
        s->virtual_clock += TOX_SCENARIO_TICK_MS;
        pthread_mutex_unlock(&s->clock_mutex);

        if (s->tick_count % 100 == 0) {
            uint64_t tick = s->tick_count;
            uint32_t active = s->num_active;
            pthread_mutex_unlock(&s->mutex);
            tox_scenario_log(s, "Tick %lu, active nodes: %u", (unsigned long)tick, active);
            pthread_mutex_lock(&s->mutex);
        }

        // 4. Release nodes for the new tick
        pthread_cond_broadcast(&s->cond_nodes);
    }

    ToxScenarioStatus result = (s->num_active == 0) ? TOX_SCENARIO_DONE : TOX_SCENARIO_TIMEOUT;
    if (result == TOX_SCENARIO_TIMEOUT) {
        tox_scenario_log(s, "Scenario TIMEOUT after %lu ms (virtual time)", (unsigned long)(tox_scenario_get_time(s) - start_clock));
    }

    // Stop nodes
    s->run_started = false;
    pthread_cond_broadcast(&s->cond_nodes);
    pthread_mutex_unlock(&s->mutex);

    for (uint32_t i = 0; i < s->num_nodes; ++i) {
        pthread_join(s->nodes[i]->thread, nullptr);
    }

    return result;
}

void tox_node_bootstrap(ToxNode *a, ToxNode *b)
{
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    memcpy(pk, b->mirror_public.dht_id, TOX_PUBLIC_KEY_SIZE);
    const uint16_t port = b->mirror_public.udp_port;

    Tox_Err_Bootstrap err;
    tox_bootstrap(a->tox, "127.0.0.1", port, pk, &err);
    if (err != TOX_ERR_BOOTSTRAP_OK) {
        tox_node_log(a, "Error bootstrapping from %s: %u", b->alias, err);
    }
}

void tox_node_friend_add(ToxNode *a, ToxNode *b)
{
    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    memcpy(pk, b->mirror_public.public_key, TOX_PUBLIC_KEY_SIZE);
    Tox_Err_Friend_Add err;
    tox_friend_add_norequest(a->tox, pk, &err);
    if (err != TOX_ERR_FRIEND_ADD_OK) {
        tox_node_log(a, "Error adding friend %s: %u", b->alias, err);
    }
}

void tox_node_reload(ToxNode *node)
{
    ck_assert(node != nullptr);
    ToxScenario *s = node->scenario;
    pthread_mutex_lock(&s->mutex);

    // 1. Save data
    size_t size = tox_get_savedata_size(node->tox);
    uint8_t *data = (uint8_t *)malloc(size);
    ck_assert(data != nullptr);
    tox_get_savedata(node->tox, data);

    Tox *old_tox = node->tox;
    Tox_Dispatch *old_dispatch = node->dispatch;

    // Invalidate node state while reloading
    node->tox = nullptr;
    node->dispatch = nullptr;

    pthread_mutex_unlock(&s->mutex);

    // 2. Kill old instance
    tox_dispatch_free(old_dispatch);
    tox_kill(old_tox);

    // 3. Create new instance from save
    Tox_Options *opts = tox_options_new(nullptr);
    ck_assert(opts != nullptr);
    tox_options_copy(opts, node->options);
    tox_options_set_savedata_type(opts, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(opts, data, size);

    Tox_Err_New err;
    Tox *new_tox = create_tox_with_port_retry(opts, node, &err);
    tox_options_free(opts);
    free(data);

    if (err != TOX_ERR_NEW_OK) {
        tox_node_log(node, "Failed to reload Tox instance: %u", err);
        return;
    }

    ck_assert_msg(new_tox != nullptr, "tox_new said OK but returned NULL");
    Tox_Dispatch *new_dispatch = tox_dispatch_new(nullptr);
    tox_events_init(new_tox);
    mono_time_set_current_time_callback(new_tox->mono_time, get_scenario_clock, s);

    pthread_mutex_lock(&s->mutex);
    node->tox = new_tox;
    node->dispatch = new_dispatch;
    pthread_mutex_unlock(&s->mutex);

    // Re-bootstrap from siblings
    for (uint32_t i = 0; i < s->num_nodes; ++i) {
        if (i != node->index) {
            tox_node_bootstrap(node, s->nodes[i]);
        }
    }
}
