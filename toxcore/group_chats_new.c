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

#define TIME_STAMP (sizeof(uint64_t))
#define GC_INVITE_REQUEST_PLAIN_SIZE (1 + (CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) )
#define GC_INVITE_REQUEST_DHT_SIZE (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + GC_INVITE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

#define GC_INVITE_RESPONSE_PLAIN_SIZE (1 + ((CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) + TIME_STAMP + CLIENT_ID_EXT_SIZE + SIGNATURE_SIZE) )
#define GC_INVITE_RESPONSE_DHT_SIZE (1 + CLIENT_ID_EXT_SIZE + crypto_box_NONCEBYTES + GC_INVITE_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)

int handle_groupchatpacket(void * _chat, IP_Port source, const uint8_t *packet, uint32_t length)
{

}

Group_Credentials *new_groupcredentials()
{
    Group_Credentials *credentials = calloc(1, sizeof(Group_Credentials));
    create_long_keypair(credentials->chat_public_key, credentials->chat_secret_key);
    unix_time_update();
    credentials->creation_time = unix_time();

    return credentials;
}


Group_Chat *new_groupchat(Networking_Core *net)
{
   	if (net == 0)
        return -1;

    // Why do we even need this?
    //unix_time_update();

    Group_Chat *chat = calloc(1, sizeof(Group_Chat));
    if (chat == NULL)
        return NULL;

    if (net == NULL)
        return NULL;

    chat->net = net;
    networking_registerhandler(chat->net, NET_PACKET_GROUP_CHATS, &handle_groupchatpacket, chat);

    // TODO: Need to handle the situation when we load this from locally stored data
    create_long_keypair(chat->self_public_key, chat->self_secret_key);

    return chat;
}

void kill_groupchat(Group_Chat *chat)
{
	// Send quit action
    // send_data(chat, 0, 0, GROUP_CHAT_QUIT);
    
    free(chat->group);
    free(chat);
}