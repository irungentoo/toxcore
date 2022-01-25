#ifndef RUN_AUTO_TEST_H
#define RUN_AUTO_TEST_H

#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"

typedef struct AutoTox {
    Tox *tox;

    uint32_t index;
    uint64_t clock;

    size_t save_size;
    uint8_t *save_state;
    bool alive;

    void *state;
} AutoTox;

bool all_connected(uint32_t tox_count, AutoTox *toxes);

bool all_friends_connected(uint32_t tox_count, AutoTox *toxes);

void iterate_all_wait(uint32_t tox_count, AutoTox *toxes, uint32_t wait);

void save_autotox(AutoTox *autotox);
void kill_autotox(AutoTox *autotox);
void reload(AutoTox *autotox);

void set_mono_time_callback(AutoTox *tox);

typedef enum Graph_Type {
    GRAPH_COMPLETE = 0,
    GRAPH_LINEAR
} Graph_Type;

typedef struct Run_Auto_Options {
    Graph_Type graph;
    void (*init_autotox)(AutoTox *autotox, uint32_t n);
} Run_Auto_Options;

extern const Run_Auto_Options default_run_auto_options;

void run_auto_test(struct Tox_Options *options, uint32_t tox_count, void test(AutoTox *autotoxes),
                   uint32_t state_size, const Run_Auto_Options *autotest_opts);

void bootstrap_tox_live_network(Tox *tox, bool enable_tcp);

#endif
