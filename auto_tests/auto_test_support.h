#ifndef RUN_AUTO_TEST_H
#define RUN_AUTO_TEST_H

#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/tox_dispatch.h"

typedef struct AutoTox {
    Tox *tox;
    Tox_Dispatch *dispatch;

    uint32_t index;
    uint64_t clock;

    size_t save_size;
    uint8_t *save_state;
    bool alive;
    bool events;

    void *state;
} AutoTox;

bool all_connected(const AutoTox *autotoxes, uint32_t tox_count);

bool all_friends_connected(const AutoTox *autotoxes, uint32_t tox_count);

void iterate_all_wait(AutoTox *autotoxes, uint32_t tox_count, uint32_t wait);

void save_autotox(AutoTox *autotox);
void kill_autotox(AutoTox *autotox);
void reload(AutoTox *autotox);

void set_mono_time_callback(AutoTox *autotox);

typedef enum Graph_Type {
    GRAPH_COMPLETE = 0,
    GRAPH_LINEAR,
} Graph_Type;

typedef struct Run_Auto_Options {
    Graph_Type graph;
    void (*init_autotox)(AutoTox *autotox, uint32_t n);
    uint16_t tcp_port;
    bool events;
} Run_Auto_Options;

Run_Auto_Options default_run_auto_options(void);

void run_auto_test(struct Tox_Options *options, uint32_t tox_count, void test(AutoTox *autotoxes),
                   uint32_t state_size, Run_Auto_Options *autotest_opts);

void bootstrap_tox_live_network(Tox *tox, bool enable_tcp);

// Use this function when setting the log callback on a Tox* object
void print_debug_log(Tox *m, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
                     const char *message, void *user_data);

// Use this function when setting the log callback on a Logger object
void print_debug_logger(void *context, Logger_Level level, const char *file, int line,
                        const char *func, const char *message, void *userdata);

Tox *tox_new_log(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data);
Tox *tox_new_log_lan(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data, bool lan_discovery);

#endif
