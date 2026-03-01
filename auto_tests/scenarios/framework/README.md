# Tox Scenario Framework

Tests should read like protocol specifications. Instead of managing manual loops
and shared global state, each "node" in a test is assigned a script (sequence of
tasks) that it executes concurrently with other nodes in a simulated
environment.

### 1. `ToxScenario`

The container for a single test case.

- Manages a collection of `ToxNode` instances.
- Owns the **Virtual Clock**. All nodes in a scenario share the same timeline,
  making timeouts and delays deterministic.
- Handles the orchestration of the event loop (`tox_iterate`).

### 2. `ToxNode`

A wrapper around a `Tox` instance and its associated state.

- Each node has its own `Tox_Dispatch`.
- Nodes are identified by a simple index or a string alias (e.g., "Alice",
  "Bob").
- Encapsulates the node's progress through its assigned Script.

### 3. `tox_node_script_cb`

A C function that defines what a node does. Because it runs in its own thread,
you can use standard C control flow, local variables, and loops.

## Example Usage

```c
void alice_script(ToxNode *self, void *ctx) {
    // Step 1: Wait for DHT connection
    WAIT_UNTIL(tox_node_is_self_connected(self));

    // Step 2: Send a message to Bob (friend 0)
    uint8_t msg[] = "Hello Bob";
    tox_friend_send_message(tox_node_get_tox(self), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), NULL);

    // Step 3: Wait for a specific response event
    WAIT_FOR_EVENT(TOX_EVENT_FRIEND_MESSAGE);
}

void test_simple_interaction() {
    ToxScenario *s = tox_scenario_new(argc, argv, 10000); // 10s virtual timeout

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, NULL);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, NULL);

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    ck_assert(res == TOX_SCENARIO_DONE);
    tox_scenario_free(s);
}
```

## Execution Model: Cooperative Multi-threading

The scenario framework uses `pthread` to provide a natural programming model
while maintaining a deterministic virtual clock:

1.  **Runner**: Orchestrates the scenario in "Ticks" (default 10ms).
2.  **Nodes**: Run concurrently in their own threads but **synchronize** at
    every tick.
3.  **Yielding**: When a script calls `WAIT_UNTIL`, `WAIT_FOR_EVENT`, or
    `tox_scenario_yield`, it yields control back to the runner.
4.  **Time Advancement**: The runner advances the virtual clock and signals all
    nodes to proceed only after all active nodes have yielded.
5.  **Barriers**: Nodes can synchronize their progress using
    `tox_scenario_barrier_wait(self)`. This function blocks the calling node
    until all other active nodes have also reached the barrier. This is useful
    for ensuring setup steps (like group creation or connection establishment)
    are complete across all nodes before proceeding to the next phase of the
    test.
