/*  nTox_win32.h
 * 
 *  Textual frontend for Tox - Windows version
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef NTOX_WIN32_H
#define NTOX_WIN32_H

#include "../core/Messenger.h"
#include "../core/network.h"

#define STRING_LENGTH 256
#define PUB_KEY_BYTES 32

void do_header();
void print_message(int friendnumber, uint8_t * string, uint16_t length);
void print_nickchange(int friendnumber, uint8_t *string, uint16_t length);
void print_statuschange(int friendnumber, uint8_t *string, uint16_t length);
void load_key();
void line_eval(char* line);
void get_input();

#endif