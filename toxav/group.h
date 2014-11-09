/**  groupav.c
 *
 *   Copyright (C) 2014 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 */

/* Audio encoding/decoding */
#include <opus.h>

#include "../toxcore/group.h"

#define GROUP_AUDIO_PACKET_ID 192

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_av_groupchat(Group_Chats *g_c);

