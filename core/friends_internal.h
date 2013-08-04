/* friends_internal.h
 *
 * friends internal stuff
 *
 * NOTE: All the text in the messages must be encoded using UTF-8
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

/* return friends count */
int get_friends_number();

/* return crypt connection id by friend id */
int get_friend_connection_id(int friendId);

/* return 1 if online; 0 if ofline */
int is_friend_online(int friendId);

/* process incoming name change packet */
void friend_change_nickname(int friendId, uint8_t* data, uint16_t size);

/* process incoming userstate change packet */
void friend_change_userstate(int friendId, uint8_t* data, uint16_t size);

/* process friend connection timeout */
void friend_disconnect(int friendId);

/* tell friends that our name has changed */
void friends_selfname_updated();

/* tell friends that our status has changed */
void friends_selfstatus_updated();

/* friends processing stuff */
void process_friends(uint8_t *self_name,
               uint16_t self_name_length,
               uint8_t *self_userstatus,
               uint16_t self_userstatus_len);


/* serialization stuff */

/* returns size of friends data (for saving) */
uint32_t friends_data_size();

/* store friends in data */
void friends_data_save(uint8_t *data);

/* loads friends from data */
int friends_data_load(uint8_t *data, uint32_t size);
