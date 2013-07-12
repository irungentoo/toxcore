/* DHT.c
* 
* An implementation of the DHT as seen in docs/DHT.txt
* 
 
    Copyright (C) 2013 Tox project All Rights Reserved.

    This file is part of Tox.

    Tox is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
    
*/




#include "DHT.h"


typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    IP_Port ip_port;
    uint32_t timestamp;
    uint32_t last_pinged;
}Client_data;
//maximum number of clients stored per friend.
#define MAX_FRIEND_CLIENTS 8
typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    Client_data client_list[MAX_FRIEND_CLIENTS];
    
}Friend;


typedef struct
{
    uint8_t client_id[CLIENT_ID_SIZE];
    IP_Port ip_port;
}Node_format;

typedef struct
{
    IP_Port ip_port;
    uint64_t ping_id;
    uint32_t timestamp;
    
}Pinged;

//Our client id/public key
uint8_t self_public_key[CLIENT_ID_SIZE];
uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

//TODO: Move these out of here and put them into the .c file.
//A list of the clients mathematically closest to ours.
#define LCLIENT_LIST 32
static Client_data close_clientlist[LCLIENT_LIST];


//Hard maximum number of friends 
#define MAX_FRIENDS 256

//Let's start with a static array for testing.
static Friend friends_list[MAX_FRIENDS];
static uint16_t num_friends;

//The list of ip ports along with the ping_id of what we sent them and a timestamp
#define LPING_ARRAY 128

static Pinged pings[LPING_ARRAY];

#define LSEND_NODES_ARRAY LPING_ARRAY/2

static Pinged send_nodes[LSEND_NODES_ARRAY];


//Compares client_id1 and client_id2 with client_id
//return 0 if both are same distance
//return 1 if client_id1 is closer.
//return 2 if client_id2 is closer.
int id_closest(uint8_t * client_id, uint8_t * client_id1, uint8_t * client_id2)//tested
{
    uint32_t i;
    for(i = 0; i < CLIENT_ID_SIZE; i++)
    {
        if(abs(client_id[i] ^ client_id1[i]) < abs(client_id[i] ^ client_id2[i]))
        {
            return 1;
        }
        else if(abs(client_id[i] ^ client_id1[i]) > abs(client_id[i] ^ client_id2[i]))
        {
            return 2;
        }
        
    }
    
    return 0;
    
}

//check if client with client_id is already in list of length length.
//if it is set it's corresponding timestamp to current time.
//if the ip_port is already in the list but associated to a different ip, change it.
//return True(1) or False(0)
//TODO: maybe optimize this.
int client_in_list(Client_data * list, uint32_t length, uint8_t * client_id, IP_Port ip_port)
{
    uint32_t i, j;
    uint32_t temp_time = unix_time();
    
    for(i = 0; i < length; i++)
    {
        //If the id for an ip/port changes, replace it.
        if(list[i].ip_port.ip.i == ip_port.ip.i &&
        list[i].ip_port.port == ip_port.port)
        {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
        }
        for(j = 0; j < CLIENT_ID_SIZE; j++)
        {
        
            if(list[i].client_id[j] != client_id[j])
            {
                break;
            }
        }
        if(j == CLIENT_ID_SIZE)
        {
            //Refresh the client timestamp.
            list[i].timestamp = temp_time;
            return 1;
        }
    }
    return 0;
    
}

//check if client with client_id is already in node format list of length length.
//return True(1) or False(0)
int client_in_nodelist(Node_format * list, uint32_t length, uint8_t * client_id)
{
    uint32_t i, j;
    for(i = 0; i < length; i++)
    {
        for(j = 0; j < CLIENT_ID_SIZE; j++)
        {
        
            if(list[i].client_id[j] != client_id[j])
            {
                break;
            }
        }
        if(j == CLIENT_ID_SIZE)
        {

            return 1;
        }
    }
    return 0;
    
}



//the number of seconds for a non responsive node to become bad.
#define BAD_NODE_TIMEOUT 130
//The max number of nodes to send with send nodes.
#define MAX_SENT_NODES 8


//Find MAX_SENT_NODES nodes closest to the client_id for the send nodes request:
//put them in the nodes_list and return how many were found.
//TODO: Make this function much more efficient.
int get_close_nodes(uint8_t * client_id, Node_format * nodes_list)
{
    uint32_t i, j, k;
    int num_nodes=0;
    uint32_t temp_time = unix_time();
    for(i = 0; i < LCLIENT_LIST; i++)
    {
        if(close_clientlist[i].timestamp + BAD_NODE_TIMEOUT > temp_time && 
        !client_in_nodelist(nodes_list, MAX_SENT_NODES,close_clientlist[i].client_id))
        //if node is good and not already in list.
        {
            if(num_nodes < MAX_SENT_NODES)
            {
                    memcpy(nodes_list[num_nodes].client_id, close_clientlist[i].client_id, CLIENT_ID_SIZE);
                    nodes_list[num_nodes].ip_port = close_clientlist[i].ip_port;
                    num_nodes++;
            }
            else for(j = 0; j < MAX_SENT_NODES; j++)
            {
                if(id_closest(client_id, nodes_list[j].client_id, close_clientlist[i].client_id) == 2)
                {
                    memcpy(nodes_list[j].client_id, close_clientlist[i].client_id, CLIENT_ID_SIZE);
                    nodes_list[j].ip_port = close_clientlist[i].ip_port;
                    break;
                }
            }
        }
        
    }
    for(i = 0; i < num_friends; i++)
    {
        for(j = 0; j < MAX_FRIEND_CLIENTS; j++)
        {
            if(friends_list[i].client_list[j].timestamp + BAD_NODE_TIMEOUT > temp_time && 
            !client_in_nodelist(nodes_list, MAX_SENT_NODES,friends_list[i].client_list[j].client_id))
            //if node is good and not already in list.
            {
                if(num_nodes < MAX_SENT_NODES)
                {
                        memcpy(nodes_list[num_nodes].client_id, friends_list[i].client_list[j].client_id, CLIENT_ID_SIZE);
                        nodes_list[num_nodes].ip_port = friends_list[i].client_list[j].ip_port;
                        num_nodes++;
                }
                else for(k = 0; k < MAX_SENT_NODES; k++)
                {
                    if(id_closest(client_id, nodes_list[k].client_id, friends_list[i].client_list[j].client_id) == 2)
                    {
                        memcpy(nodes_list[k].client_id, friends_list[i].client_list[j].client_id, CLIENT_ID_SIZE);
                        nodes_list[k].ip_port = friends_list[i].client_list[j].ip_port;
                        break;
                    }
                }
            }
        }        
    }
    
    return num_nodes;
    
}



//replace first bad (or empty) node with this one
//return 0 if successful
//return 1 if not (list contains no bad nodes)
int replace_bad(Client_data * list, uint32_t length, uint8_t * client_id, IP_Port ip_port)//tested
{
    uint32_t i;
    uint32_t temp_time = unix_time();
    for(i = 0; i < length; i++)
    {
        if(list[i].timestamp + BAD_NODE_TIMEOUT < temp_time)//if node is bad.
        {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = temp_time;
            return 0;
        }
    }
    return 1;
    
}

//replace the first good node that is further to the comp_client_id than that of the client_id in the list
int replace_good(Client_data * list, uint32_t length, uint8_t * client_id, IP_Port ip_port, uint8_t * comp_client_id)
{
    uint32_t i;
    uint32_t temp_time = unix_time();
    
    for(i = 0; i < length; i++)
    {
        if(id_closest(comp_client_id, list[i].client_id, client_id) == 2)
        {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = temp_time;
            return 0;
        }
    }
    return 1;
    
}

//Attempt to add client with ip_port and client_id to the friends client list and close_clientlist
void addto_lists(IP_Port ip_port, uint8_t * client_id)
{
    uint32_t i;
    
    //NOTE: current behavior if there are two clients with the same id is to only keep one (the first one)
    if(!client_in_list(close_clientlist, LCLIENT_LIST, client_id, ip_port))
    {
         
        if(replace_bad(close_clientlist, LCLIENT_LIST, client_id, ip_port))
        {
            //if we can't replace bad nodes we try replacing good ones
            replace_good(close_clientlist, LCLIENT_LIST, client_id, ip_port, self_public_key);
        }
        
    }
    for(i = 0; i < num_friends; i++)
    {
        if(!client_in_list(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id, ip_port))
        {
            
            if(replace_bad(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id, ip_port))
            {
                //if we can't replace bad nodes we try replacing good ones
                replace_good(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id, ip_port, self_public_key);
            }
        }  
    }
}


//ping timeout in seconds
#define PING_TIMEOUT 5
//check if we are currently pinging an ip_port and/or a ping_id
//Variables with values of zero will not be checked.
//if we are already, return 1
//else return 0
//TODO: Maybe optimize this
int is_pinging(IP_Port ip_port, uint64_t ping_id)
{
    uint32_t i;
    uint8_t pinging;
    uint32_t temp_time = unix_time();

    for(i = 0; i < LPING_ARRAY; i++ )
    {
        if((pings[i].timestamp + PING_TIMEOUT) > temp_time)
        {
            pinging = 0;
            if(ip_port.ip.i != 0)
            {
                if(pings[i].ip_port.ip.i == ip_port.ip.i &&
                pings[i].ip_port.port == ip_port.port)
                {
                        pinging++;
                }
            }
            if(ping_id != 0)
            {
                if(pings[i].ping_id == ping_id)
                {
                        pinging++;
                }
            }
            if(pinging == (ping_id != 0) + (ip_port.ip.i != 0))
            {
                    return 1;
            }
            
        }
    }

    return 0;
    
}


//Same as last function but for get_node requests.
int is_gettingnodes(IP_Port ip_port, uint64_t ping_id)
{
    uint32_t i;
    uint8_t pinging;
    uint32_t temp_time = unix_time();

    for(i = 0; i < LPING_ARRAY; i++ )
    {
        if((send_nodes[i].timestamp + PING_TIMEOUT) > temp_time)
        {
            pinging = 0;
            if(ip_port.ip.i != 0)
            {
                if(send_nodes[i].ip_port.ip.i == ip_port.ip.i &&
                send_nodes[i].ip_port.port == ip_port.port)
                {
                        pinging++;
                }
            }
            if(ping_id != 0)
            {
                if(send_nodes[i].ping_id == ping_id)
                {
                        pinging++;
                }
            }
            if(pinging == (ping_id != 0) + (ip_port.ip.i != 0))
            {
                    return 1;
            }
            
        }
    }

    return 0;
    
}


//Add a new ping request to the list of ping requests
//returns the ping_id to put in the ping request
//returns 0 if problem.
//TODO: Maybe optimize this
uint64_t add_pinging(IP_Port ip_port)
{
    uint32_t i, j;
    uint64_t ping_id = ((uint64_t)random_int() << 32) + random_int();
    uint32_t temp_time = unix_time();
    
    for(i = 0; i < PING_TIMEOUT; i++ )
    {
        for(j = 0; j < LPING_ARRAY; j++ )
        {
            if((pings[j].timestamp + PING_TIMEOUT - i) < temp_time)
            {
                    pings[j].timestamp = temp_time;
                    pings[j].ip_port = ip_port;
                    pings[j].ping_id = ping_id;
                    return ping_id;
            }
        }
    }
    return 0;
    
}

//Same but for get node requests
uint64_t add_gettingnodes(IP_Port ip_port)
{
    uint32_t i, j;
    uint64_t ping_id = ((uint64_t)random_int() << 32) + random_int();
    uint32_t temp_time = unix_time();
    
    for(i = 0; i < PING_TIMEOUT; i++ )
    {
        for(j = 0; j < LSEND_NODES_ARRAY; j++ )
        {
            if((send_nodes[j].timestamp + PING_TIMEOUT - i) < temp_time)
            {
                    send_nodes[j].timestamp = temp_time;
                    send_nodes[j].ip_port = ip_port;
                    send_nodes[j].ping_id = ping_id;
                    return ping_id;
            }
        }
    }
    return 0;
    
}



//send a ping request
//Ping request only works if none has been sent to that ip/port in the last 5 seconds.
static int pingreq(IP_Port ip_port, uint8_t * public_key)
{
    if(memcmp(public_key, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is gonna be sent to ourself
    {
        return 1;
    }
    
    if(is_pinging(ip_port, 0))
    {
        return 1;
    }
    
    uint64_t ping_id = add_pinging(ip_port);
    if(ping_id == 0)
    {
        return 1;
    }
    
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING];
    uint8_t encrypt[sizeof(ping_id) + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    
    int len = encrypt_data(public_key, self_secret_key, nonce, (uint8_t *)&ping_id, sizeof(ping_id), encrypt);
    if(len != sizeof(ping_id) + ENCRYPTION_PADDING)
    {
        return -1;
    }
    data[0] = 0;
    memcpy(data + 1, self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);
    
    return sendpacket(ip_port, data, sizeof(data));
    
}


//send a ping response
static int pingres(IP_Port ip_port, uint8_t * public_key, uint64_t ping_id)
{
    if(memcmp(public_key, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is gonna be sent to ourself
    {
        return 1;
    }
    
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING];
    uint8_t encrypt[sizeof(ping_id) + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    
    int len = encrypt_data(public_key, self_secret_key, nonce, (uint8_t *)&ping_id, sizeof(ping_id), encrypt);
    if(len != sizeof(ping_id) + ENCRYPTION_PADDING)
    {
        return -1;
    }
    data[0] = 1;
    memcpy(data + 1, self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);
    
    return sendpacket(ip_port, data, sizeof(data));
    
}

//send a getnodes request
static int getnodes(IP_Port ip_port, uint8_t * public_key, uint8_t * client_id)
{
    if(memcmp(public_key, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is gonna be sent to ourself
    {
        return 1;
    }
    
    if(is_gettingnodes(ip_port, 0))
    {
        return 1;
    }
    
    uint64_t ping_id = add_gettingnodes(ip_port);
    
    if(ping_id == 0)
    {
        return 1;
    }
    
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t plain[sizeof(ping_id) + CLIENT_ID_SIZE];
    uint8_t encrypt[sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    
    memcpy(plain, &ping_id, sizeof(ping_id));
    memcpy(plain + sizeof(ping_id), client_id, CLIENT_ID_SIZE);
    
    int len = encrypt_data(public_key, self_secret_key, nonce, plain, sizeof(ping_id) + CLIENT_ID_SIZE, encrypt);
    
    if(len != sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING)
    {
        return -1;
    }
    data[0] = 2;
    memcpy(data + 1, self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);
    return sendpacket(ip_port, data, sizeof(data));
    
}


//send a send nodes response
static int sendnodes(IP_Port ip_port, uint8_t * public_key, uint8_t * client_id, uint64_t ping_id)
{
    if(memcmp(public_key, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is gonna be sent to ourself
    {
        return 1;
    }
    
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) 
                                    + sizeof(Node_format) * MAX_SENT_NODES + ENCRYPTION_PADDING];
                                    
    Node_format nodes_list[MAX_SENT_NODES];
    int num_nodes = get_close_nodes(client_id, nodes_list);
    
    if(num_nodes == 0)
    {
        return 0;
    }
    
    uint8_t plain[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES];
    uint8_t encrypt[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);
    
    memcpy(plain, &ping_id, sizeof(ping_id));
    memcpy(plain + sizeof(ping_id), nodes_list, num_nodes * sizeof(Node_format));
    
    int len = encrypt_data(public_key, self_secret_key, nonce, plain, 
                                       sizeof(ping_id) + num_nodes * sizeof(Node_format), encrypt);
    
    if(len != sizeof(ping_id) + num_nodes * sizeof(Node_format) + ENCRYPTION_PADDING)
    {
        return -1;
    }
    
    data[0] = 3;
    memcpy(data + 1, self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);
    
    return sendpacket(ip_port, data, 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + len);
   
}




//Packet handling functions
//One to handle each types of packets we receive
//return 0 if handled correctly, 1 if packet is bad.
int handle_pingreq(uint8_t * packet, uint32_t length, IP_Port source)
{
    uint64_t ping_id;
    if(length != 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING)
    {
        return 1;
    }
    if(memcmp(packet + 1, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is from ourself.
    {
        return 1;
    }
    
    
    
    int len = decrypt_data(packet + 1, self_secret_key, packet + 1 + CLIENT_ID_SIZE, 
                                       packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, 
                                       sizeof(ping_id) + ENCRYPTION_PADDING, (uint8_t *)&ping_id);
    if(len != sizeof(ping_id))
    {
        return 1;
    }

    
    pingres(source, packet + 1, ping_id);
    
    pingreq(source, packet + 1);//TODO: make this smarter?
 
    return 0;
    
}

int handle_pingres(uint8_t * packet, uint32_t length, IP_Port source)
{
    uint64_t ping_id;
    if(length != 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING)
    {
        return 1;
    }
    if(memcmp(packet + 1, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is from ourself.
    {
        return 1;
    }
    
    
    
    int len = decrypt_data(packet + 1, self_secret_key, packet + 1 + CLIENT_ID_SIZE, 
                                       packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, 
                                       sizeof(ping_id) + ENCRYPTION_PADDING, (uint8_t *)&ping_id);
    if(len != sizeof(ping_id))
    {
        return 1;
    }
    
    if(is_pinging(source, ping_id))
    {
        addto_lists(source, packet + 1);
        return 0;
    }
    return 1;
    
}

int handle_getnodes(uint8_t * packet, uint32_t length, IP_Port source)
{
    uint64_t ping_id;
    if(length != 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING)
    {
        return 1;
    }
    if(memcmp(packet + 1, self_public_key, CLIENT_ID_SIZE) == 0)//check if packet is from ourself.
    {
        return 1;
    }
    
    uint8_t plain[sizeof(ping_id) + CLIENT_ID_SIZE];
    
    int len = decrypt_data(packet + 1, self_secret_key, packet + 1 + CLIENT_ID_SIZE, 
                                       packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, 
                                       sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING, plain);
    
    if(len != sizeof(ping_id) + CLIENT_ID_SIZE)
    {
        return 1;
    }
    
    
    memcpy(&ping_id, plain, sizeof(ping_id));
    sendnodes(source, packet + 1, plain + sizeof(ping_id), ping_id);
    
    pingreq(source, packet + 1);//TODO: make this smarter?
    
    return 0;
    
}

int handle_sendnodes(uint8_t * packet, uint32_t length, IP_Port source)
{
    uint64_t ping_id;
    if(length > (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id)
                 + sizeof(Node_format) * MAX_SENT_NODES + ENCRYPTION_PADDING) || 
    (length - (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) 
                 + ENCRYPTION_PADDING)) % (sizeof(Node_format)) != 0 ||
     length < 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) 
                                 + sizeof(Node_format) + ENCRYPTION_PADDING)
    {
        return 1;
    } 
    uint32_t num_nodes = (length - (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES 
                         + sizeof(ping_id) + ENCRYPTION_PADDING)) / sizeof(Node_format);
    
    uint8_t plain[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES]; 
    
    int len = decrypt_data(packet + 1, self_secret_key, packet + 1 + CLIENT_ID_SIZE, 
                                       packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, 
                                       sizeof(ping_id) + num_nodes * sizeof(Node_format) + ENCRYPTION_PADDING, plain);
    
    
    if(len != sizeof(ping_id) + num_nodes * sizeof(Node_format))
    {
        return 1;
    }
        
    memcpy(&ping_id, plain, sizeof(ping_id));
    if(!is_gettingnodes(source, ping_id))
    {
        return 1;
    }
    
    Node_format nodes_list[MAX_SENT_NODES];
    memcpy(nodes_list, plain + sizeof(ping_id), num_nodes * sizeof(Node_format));
    
    uint32_t i;
    for(i = 0; i < num_nodes; i++)
    {
        pingreq(nodes_list[i].ip_port, nodes_list[i].client_id);
    }
    
    addto_lists(source, packet + 1);
    return 0;
    
}

//END of packet handling functions



int DHT_addfriend(uint8_t * client_id)
{
    //TODO:Maybe make the array of friends dynamic instead of a static array with MAX_FRIENDS
    if(MAX_FRIENDS > num_friends)
    {
        memcpy(friends_list[num_friends].client_id, client_id, CLIENT_ID_SIZE);
        num_friends++;
    return 0;
    }
    return 1;
    
}





int DHT_delfriend(uint8_t * client_id)
{
    uint32_t i;
    for(i = 0; i < num_friends; i++)
    {
        if(memcmp(friends_list[i].client_id, client_id, CLIENT_ID_SIZE) == 0)//Equal
        {
            memcpy(friends_list[num_friends].client_id, friends_list[i].client_id, CLIENT_ID_SIZE);
            num_friends--;
            return 0;
        }
    }
    return 1;
    
}




//TODO: Optimize this.
IP_Port DHT_getfriendip(uint8_t * client_id)
{
    uint32_t i, j;
    IP_Port empty = {{{0}}, 0};
    
    for(i = 0; i < num_friends; i++)
    {
        if(memcmp(friends_list[i].client_id, client_id, CLIENT_ID_SIZE) == 0)//Equal
        {
            for(j = 0; j < MAX_FRIEND_CLIENTS; j++)
            {
                if(memcmp(friends_list[i].client_list[j].client_id, client_id, CLIENT_ID_SIZE) == 0)
                {
                    return friends_list[i].client_list[j].ip_port;
                }
                
            }
                
            return empty;
        }
    }
    empty.ip.i = 1;
    return empty;
    
}
    
    



int DHT_handlepacket(uint8_t * packet, uint32_t length, IP_Port source)
{
    switch (packet[0]) {
    case 0:
        return handle_pingreq(packet, length, source);   
        
    case 1:
        return handle_pingres(packet, length, source); 
        
    case 2:
        return handle_getnodes(packet, length, source); 
        
    case 3:
        return handle_sendnodes(packet, length, source);
        
    default: 
        return 1;
        
    }
    
    return 0;

}

//The timeout after which a node is discarded completely.
#define Kill_NODE_TIMEOUT 300

//ping interval in seconds for each node in our lists.
#define PING_INTERVAL 60

//ping interval in seconds for each random sending of a get nodes request.
#define GET_NODE_INTERVAL 10

//Ping each client in the "friends" list every 60 seconds.
//Send a get nodes request every 20 seconds to a random good node for each "friend" in our "friends" list.

static uint32_t friend_lastgetnode[MAX_FRIENDS];


void doDHTFriends()
{
    uint32_t i, j;
    uint32_t temp_time = unix_time();
    uint32_t num_nodes = 0;
    uint32_t rand_node;
    uint32_t index[MAX_FRIEND_CLIENTS];
    
    for(i = 0; i < num_friends; i++)
    {
        for(j = 0; j < MAX_FRIEND_CLIENTS; j++)
        {
            if(friends_list[i].client_list[j].timestamp + Kill_NODE_TIMEOUT > temp_time)//if node is not dead.
            {
                if((friends_list[i].client_list[j].last_pinged + PING_INTERVAL) <= temp_time)
                {
                    pingreq(friends_list[i].client_list[j].ip_port, friends_list[i].client_list[j].client_id);
                    friends_list[i].client_list[j].last_pinged = temp_time;
                }
                if(friends_list[i].client_list[j].timestamp + BAD_NODE_TIMEOUT > temp_time)//if node is good.
                {
                    index[num_nodes] = j;
                    num_nodes++;
                }
            }
        }
        if(friend_lastgetnode[i] + GET_NODE_INTERVAL <= temp_time && num_nodes != 0)
        {
            rand_node = rand() % num_nodes;
            getnodes(friends_list[i].client_list[index[rand_node]].ip_port, 
                     friends_list[i].client_list[index[rand_node]].client_id, 
                     friends_list[i].client_id);
            friend_lastgetnode[i] = temp_time;
        }
    }
}

static uint32_t close_lastgetnodes;

//Ping each client in the close nodes list every 60 seconds.
//Send a get nodes request every 20 seconds to a random good node in the list.
void doClose()//tested
{
    uint32_t i;
    uint32_t temp_time = unix_time();
    uint32_t num_nodes = 0;
    uint32_t rand_node;
    uint32_t index[LCLIENT_LIST];
    
    for(i = 0; i < LCLIENT_LIST; i++)
    {
        if(close_clientlist[i].timestamp + Kill_NODE_TIMEOUT > temp_time)//if node is not dead.
        {
            if((close_clientlist[i].last_pinged + PING_INTERVAL) <= temp_time)
            {
                pingreq(close_clientlist[i].ip_port, close_clientlist[i].client_id);
                close_clientlist[i].last_pinged = temp_time;
            }
            if(close_clientlist[i].timestamp + BAD_NODE_TIMEOUT > temp_time)//if node is good.
            {
                index[num_nodes] = i;
                num_nodes++;
            }
        }   
    }
    
    if(close_lastgetnodes + GET_NODE_INTERVAL <= temp_time && num_nodes != 0)
    {
        rand_node = rand() % num_nodes;
        getnodes(close_clientlist[index[rand_node]].ip_port, 
                 close_clientlist[index[rand_node]].client_id, 
                 self_public_key);
        close_lastgetnodes = temp_time;
    }
    
}



void doDHT()
{
    doClose();
    doDHTFriends();
}




void DHT_bootstrap(IP_Port ip_port, uint8_t * public_key)
{

    getnodes(ip_port, public_key, self_public_key);
    
}

