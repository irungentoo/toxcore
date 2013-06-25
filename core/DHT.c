#include "DHT.h"

uint16_t num_friends;
char self_client_id[CLIENT_ID_SIZE];
int sock;
#define LCLIENT_LIST 32
Client_data close_clientlist[LCLIENT_LIST];

Friend friends_list[256];
uint16_t num_friends;

#define LPING_ARRAY 128
Pinged pings[LPING_ARRAY];

#define LSEND_NODES_ARRAY LPING_ARRAY/2
Pinged send_nodes[LSEND_NODES_ARRAY];


//Basic network functions:
//TODO: put them somewhere else than here

//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {AF_INET, ip_port.ip.i, ip_port.port};
    
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

//Function to recieve data, ip and port of sender is put into ip_port
//the packet data into data
//the packet length into length.
int recievepacket(IP_Port * ip_port, char * data, uint32_t * length)
{
    ADDR addr;
    int32_t addrlen = sizeof(addr);
    (*(int *)length) = recvfrom(sock, data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);
    if(*(int *)length == -1)
    {
        //nothing recieved
        return -1;
    }
    ip_port->ip = addr.ip;
    ip_port->port = addr.port;
    return 0;
}



//Compares client_id1 and client_id2 with client_id
//return 0 if both are same distance
//return 1 if client_id1 is closer.
//return 2 if client_id2 is closer.
int id_closest(char * client_id, char * client_id1, char * client_id2)
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
//return True(1) or False(0)
int client_in_list(Client_data * list, uint32_t length, char * client_id)
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
        if((j - 1) == CLIENT_ID_SIZE)
        {
            //Refresh the client timestamp.
            list[i].timestamp = unix_time();
            return 1;
        }
    }
    return 0;
}

//the number of seconds for a non responsive node to become bad.
#define BAD_NODE_TIMEOUT 130

//replace first bad (or empty) node with this one
//return 0 if successfull
//return 1 if not (list contains no bad nodes)
int replace_bad(Client_data * list, uint32_t length, char * client_id, IP_Port ip_port)
{
    uint32_t i;
    for(i = 0; i < length; i++)
    {
        if(list[i].timestamp + BAD_NODE_TIMEOUT < unix_time())
        {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = unix_time();
            return 0;
        }
    }
    return 1;
}

//replace the first good node further to the comp_client_id than that of the client_id 
int replace_good(Client_data * list, uint32_t length, char * client_id, IP_Port ip_port, char * comp_client_id)
{
    uint32_t i;
    for(i = 0; i < length; i++)
    {
        if(id_closest(comp_client_id, list[i].client_id, client_id) == 2)
        {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = unix_time();
            return 0;
        }
    }
    return 1;
}

//Attempt to add client with ip_port and client_id to the friends client list and close_clientlist
int addto_lists(IP_Port ip_port, char * client_id)
{
    uint32_t i;
    
    //NOTE: current behaviour if there are two clients with the same id is to only keep one (the first one)
    if(!client_in_list(close_clientlist, LCLIENT_LIST, client_id))
    {
         
        if(replace_bad(close_clientlist, LCLIENT_LIST, client_id, ip_port))
        {
            //if we can't replace bad nodes we try replacing good ones
            replace_good(close_clientlist, LCLIENT_LIST, client_id, ip_port, self_client_id);
        }
        
    }
    for(i = 0; i < num_friends; i++)
    {
        if(!client_in_list(friends_list[i].client_list, LCLIENT_LIST, client_id))
        {
            
            if(replace_bad(friends_list[i].client_list, LCLIENT_LIST, client_id, ip_port))
            {
                //if we can't replace bad nodes we try replacing good ones
                replace_good(friends_list[i].client_list, LCLIENT_LIST, client_id, ip_port, self_client_id);
            }
            
        }  
    }
    
    return 0;
}


//ping timeout in seconds
#define PING_TIMEOUT 10
//check if we are currently pinging an ip_port
//if we are already, return 1
//else return 0
//TODO: Maybe optimize this
int is_pinging(IP_Port ip_port)
{
    uint32_t i;
    
    for(i = 0; i < LPING_ARRAY; i++ )
    {
        if((pings[i].timestamp + PING_TIMEOUT) > unix_time() && 
        pings[i].ip_port.ip.i == ip_port.ip.i &&
        pings[i].ip_port.port == ip_port.port)
        {
                return 1;
        }
    }

    return 0;
    
}


//Same as last function but for get_node requests.
int is_gettingnodes(IP_Port ip_port)
{
    uint32_t i;
    
    for(i = 0; i < LSEND_NODES_ARRAY; i++ )
    {
        if((send_nodes[i].timestamp + PING_TIMEOUT) > unix_time() && 
        send_nodes[i].ip_port.ip.i == ip_port.ip.i &&
        send_nodes[i].ip_port.port == ip_port.port)
        {
                return 1;
        }
    }

    return 0;
    
}

//Add a new ping request to the list of ping requests
//returns the ping_id to put in the ping request
//TODO: Maybe optimize this
int add_pinging(IP_Port ip_port)
{
    uint32_t i, j;
    int ping_id = rand();
    for(i = 0; i < PING_TIMEOUT; i++ )
    {
        for(j = 0; j < LPING_ARRAY; j++ )
        {
            if((pings[j].timestamp + PING_TIMEOUT - i) < unix_time())
            {
                    pings[j].timestamp = unix_time();
                    pings[j].ip_port = ip_port;
                    pings[j].ping_id = ping_id;
                    return ping_id;
            }
        }
    }
}

//Same but for get node requests
int add_gettingnodes(IP_Port ip_port)
{
    uint32_t i, j;
    int ping_id = rand();
    for(i = 0; i < PING_TIMEOUT; i++ )
    {
        for(j = 0; j < LSEND_NODES_ARRAY; j++ )
        {
            if((send_nodes[j].timestamp + PING_TIMEOUT - i) < unix_time())
            {
                    send_nodes[j].timestamp = unix_time();
                    send_nodes[j].ip_port = ip_port;
                    send_nodes[j].ping_id = ping_id;
                    return ping_id;
            }
        }
    }
}


//send a ping request
int pingreq(IP_Port ip_port)
{
    if(is_pinging(ip_port))
    {
        return 1;
    }
    
    int ping_id = add_pinging(ip_port);
    
    char data[5 + CLIENT_ID_SIZE];
    data[0] = 0;
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    
    return sendpacket(ip_port, data, sizeof(data));
    
}


//send a ping response
int pingres(IP_Port ip_port, uint32_t ping_id)
{
    char data[5 + CLIENT_ID_SIZE];
    data[0] = 1;
    
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    
    return sendpacket(ip_port, data, sizeof(data));
    
}

//send a getnodes request
int getnodes(IP_Port ip_port, char * client_id)
{
    if(is_gettingnodes(ip_port))
    {
        return 1;
    }
    
    int ping_id = add_pinging(ip_port);
    
    char data[5 + CLIENT_ID_SIZE*2];
    data[0] = 2;
    
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    memcpy(data + 5 + CLIENT_ID_SIZE, client_id, CLIENT_ID_SIZE);

    return sendpacket(ip_port, data, sizeof(data));
}

//send a send nodes response
//Currently incomplete: missing bunch of stuff
int sendnodes(IP_Port ip_port, char * client_id)
{
   char data[5 + (CLIENT_ID_SIZE + 6)*8];
   data[0] = 3;
   
   memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
   memcpy(data + 5 + CLIENT_ID_SIZE, client_id, CLIENT_ID_SIZE);
   
   sendpacket(ip_port, data, sizeof(data));

   return 0;
}




//Packet handling functions
//One to handle each types of packets we recieve

int handle_pingreq(char * packet, uint32_t length, IP_Port source)
{
    if(length != 5 + CLIENT_ID_SIZE)
    {
        return 1;
    }
    
    uint32_t ping_id;
    
    memcpy(&ping_id, packet + 1, 4);
    pingres(source, ping_id);
    
    
    
    return 0;
}

int handle_pingres(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE))
    {
        return 1;
    }
    
    addto_lists(source, packet + 5);
}

int handle_getnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE*2))
    {
        return 1;
    }
    
    
    
    
    return 0;   
}

int handle_sendnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length > 325 || (length - 5) % (CLIENT_ID_SIZE + 6) != 0)
    {
        return 1;
    } 
    addto_lists(source, packet + 5);
    
}

//END of packet handling functions



void addfriend(char * client_id)
{
    //TODO: Make the array of friends dynamic instead of a static array with 256 places..
    //WARNING:This will segfault if the number of friends exceeds 256.
    memcpy(friends_list[num_friends].client_id, client_id, CLIENT_ID_SIZE);
    num_friends++;
}





char delfriend(char * client_id)
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





IP_Port getfriendip(char * client_id)
{
    IP_Port ret;
    
    return ret;
}




int DHT_recvpacket(char * packet, uint32_t length, IP_Port source)
{
    switch (packet[0]) {
    case 0:
        handle_pingreq(packet, length, source);
        break;        
    case 1:
        handle_pingres(packet, length, source);
        break;        
    case 2:
        handle_getnodes(packet, length, source);
        break;        
    case 3:
        handle_sendnodes(packet, length, source);
        break;
    default: 
        return 1;
        
    }
    

}

//Ping each client in the "friends" list every 60 seconds.
//Send a get nodes request every 20 seconds to a random good node for each "friend" in our "friends" list.
void doFriends()
{
    
    
    
}


void doClose()
{
    
    
    
}



void doDHT()
{
    
    
    
}




void bootstrap(IP_Port ip_port)
{

    getnodes(ip_port, self_client_id);
    
}

