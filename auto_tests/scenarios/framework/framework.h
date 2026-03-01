#ifndef TOX_TEST_FRAMEWORK_H
#define TOX_TEST_FRAMEWORK_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../check_compat.h"
#include "../../../toxcore/attributes.h"
#include "../../../toxcore/ccompat.h"
#include "../../../toxcore/tox.h"
#include "../../../toxcore/tox_dispatch.h"

// --- Constants ---
#define TOX_SCENARIO_TICK_MS 50

// --- Opaque Types ---
typedef struct ToxNode ToxNode;
typedef struct ToxScenario ToxScenario;

typedef enum {
    TOX_SCENARIO_OK,
    TOX_SCENARIO_RUNNING,
    TOX_SCENARIO_DONE,
    TOX_SCENARIO_ERROR,
    TOX_SCENARIO_TIMEOUT
} ToxScenarioStatus;

/**
 * A script function that defines the behavior of a node.
 */
typedef void tox_node_script_cb(ToxNode *self, void *ctx);

// --- Core API ---

ToxScenario *tox_scenario_new(int argc, char *const argv[], uint64_t timeout_ms);
void tox_scenario_free(ToxScenario *s);

/**
 * Adds a node to the scenario and assigns it a script.
 * @param ctx_size The size of the context struct to be mirrored (snapshot) at each tick.
 */
ToxNode *tox_scenario_add_node(ToxScenario *s, const char *alias, tox_node_script_cb *script, void *ctx, size_t ctx_size);

/**
 * Extended version of add_node that accepts custom Tox_Options.
 */
ToxNode *tox_scenario_add_node_ex(ToxScenario *s, const char *alias, tox_node_script_cb *script, void *ctx, size_t ctx_size, const Tox_Options *options);

/**
 * Returns a node by its index in the scenario.
 */
ToxNode *tox_scenario_get_node(ToxScenario *s, uint32_t index);

/**
 * Runs the scenario until all nodes complete their scripts or timeout occurs.
 */
ToxScenarioStatus tox_scenario_run(ToxScenario *s);

// --- Logging API ---

/**
 * Logs a message with the node's alias/index and current virtual time.
 */
void tox_node_log(ToxNode *node, const char *format, ...) GNU_PRINTF(2, 3);

/**
 * Logs a message from the scenario runner with current virtual time.
 */
void tox_scenario_log(const ToxScenario *s, const char *format, ...) GNU_PRINTF(2, 3);

// --- Script API (Callable from within scripts) ---

/**
 * Returns the underlying Tox instance.
 */
Tox *tox_node_get_tox(const ToxNode *node);

/**
 * Returns the mirrored address of the node.
 */
void tox_node_get_address(const ToxNode *node, uint8_t *address);

/**
 * Returns the scenario this node belongs to.
 */
ToxScenario *tox_node_get_scenario(const ToxNode *node);

/**
 * Returns the alias of the node.
 */
const char *tox_node_get_alias(const ToxNode *node);

/**
 * Returns the index of the node in the scenario.
 */
uint32_t tox_node_get_index(const ToxNode *node);

/**
 * Returns the script context associated with this node.
 */
void *tox_node_get_script_ctx(const ToxNode *node);

/**
 * Returns a read-only snapshot of a peer's context.
 * The snapshot is updated at every tick.
 */
const void *tox_node_get_peer_ctx(const ToxNode *node);

/**
 * Returns the event dispatcher associated with this node.
 */
Tox_Dispatch *tox_node_get_dispatch(const ToxNode *node);

/**
 * Predicate helpers for common wait conditions.
 */
bool tox_node_is_self_connected(const ToxNode *node);
bool tox_node_is_friend_connected(const ToxNode *node, uint32_t friend_number);

Tox_Connection tox_node_get_connection_status(const ToxNode *node);
Tox_Connection tox_node_get_friend_connection_status(const ToxNode *node, uint32_t friend_number);

/**
 * Conference helpers.
 */
uint32_t tox_node_get_conference_peer_count(const ToxNode *node, uint32_t conference_number);

/**
 * Network simulation.
 */
void tox_node_set_offline(ToxNode *node, bool offline);
bool tox_node_is_offline(const ToxNode *node);

/**
 * Returns true if the node has finished its script.
 */
bool tox_node_is_finished(const ToxNode *node);

/**
 * High-level predicates for specific state changes.
 */
bool tox_node_friend_name_is(const ToxNode *node, uint32_t friend_number, const uint8_t *name, size_t length);
bool tox_node_friend_status_message_is(const ToxNode *node, uint32_t friend_number, const uint8_t *msg, size_t length);
bool tox_node_friend_typing_is(const ToxNode *node, uint32_t friend_number, bool is_typing);

/**
 * Yields execution to the next tick.
 */
void tox_scenario_yield(ToxNode *self);

/**
 * Returns the current virtual time in milliseconds.
 */
uint64_t tox_scenario_get_time(ToxScenario *s);

/**
 * Returns true if the scenario is still running.
 */
bool tox_scenario_is_running(ToxNode *self);

/**
 * Blocks until a condition is true. Polls every tick.
 */
#define WAIT_UNTIL(cond) do { while(!(cond) && tox_scenario_is_running(self)) { tox_scenario_yield(self); } } while(0)

/**
 * Blocks until a specific event is observed.
 */
void tox_scenario_wait_for_event(ToxNode *self, Tox_Event_Type type);

#define WAIT_FOR_EVENT(type) tox_scenario_wait_for_event(self, type)

/**
 * Synchronization barriers.
 * Blocks until all active nodes have reached this barrier.
 */
void tox_scenario_barrier_wait(ToxNode *self);

/**
 * High-level wait helpers.
 */
void tox_node_wait_for_self_connected(ToxNode *self);
void tox_node_wait_for_friend_connected(ToxNode *self, uint32_t friend_number);

// --- High-Level Helpers ---

void tox_node_bootstrap(ToxNode *a, ToxNode *b);
void tox_node_friend_add(ToxNode *a, ToxNode *b);

/**
 * Reloads a node from its own savedata.
 * This simulates a client restart.
 */
void tox_node_reload(ToxNode *node);

#endif // TOX_TEST_FRAMEWORK_H
