/*
 * util.h -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

uint64_t now();
uint64_t random_64b();
bool ipp_eq(IP_Port a, IP_Port b);
bool id_eq(clientid_t *dest, clientid_t *src);
void id_cpy(clientid_t *dest, clientid_t *src);
bool system_big_endian();
uint8_t reverse_bits(uint8_t x);
