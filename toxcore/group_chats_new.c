/* group_chats.c
 *
 * An implementation of massive text only group chats.
 *
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
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "group_chats_new.h"
#include "LAN_discovery.h"
#include "util.h"

Group_Chat *new_groupchat(Networking_Core *net)
{
   	if (net == 0)
        return -1;

    unix_time_update();

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    chat->net = net;

    // TODO: Need to handle the situation when we load this from locally stored data
    crypto_box_keypair(chat->self_public_key, chat->self_secret_key);

    return chat;
}

void kill_groupchat(Group_Chat *chat)
{
	// Send quit action
    // send_data(chat, 0, 0, GROUP_CHAT_QUIT);
    
    free(chat->group);
    free(chat);
}