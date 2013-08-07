/*
 * ping.h -- Buffered pinging using cyclic arrays.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

#include <stdbool.h>

void init_ping();
uint64_t add_ping(tox_IP_Port ipp);
bool is_pinging(tox_IP_Port ipp, uint64_t ping_id);

