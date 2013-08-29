/*
 * util.h -- Utilities.
 *
 * This file is donated to the Tox Project.
 * Copyright 2013  plutooo
 */

uint64_t now();
uint64_t random_64b();
bool ipp_eq(IP_Port a, IP_Port b);
bool id_eq(uint8_t *dest, uint8_t *src);
void id_cpy(uint8_t *dest, uint8_t *src);
