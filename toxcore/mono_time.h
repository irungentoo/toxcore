#ifndef C_TOXCORE_TOXCORE_MONO_TIME_H
#define C_TOXCORE_TOXCORE_MONO_TIME_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Mono_Time Mono_Time;

Mono_Time *mono_time_new(void);
void mono_time_free(Mono_Time *monotime);

void mono_time_update(Mono_Time *monotime);
uint64_t mono_time_get(const Mono_Time *monotime);
bool mono_time_is_timeout(const Mono_Time *monotime, uint64_t timestamp, uint64_t timeout);

// TODO(#405): Use per-tox monotime, delete these functions.
void unix_time_update(void);
uint64_t unix_time(void);
int is_timeout(uint64_t timestamp, uint64_t timeout);

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void);

#ifdef __cplusplus
}
#endif

#endif  // C_TOXCORE_TOXCORE_MONO_TIME_H
