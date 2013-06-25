#include "DHT.h"


//Basic network functions:
//TODO: put them somewhere else than here

//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {AF_INET, ip_port.port, ip_port.ip}; 
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

//Function to recieve data, ip and port of sender is put into ip_port
//the packet data into data
//the packet length into length.
int recievepacket(IP_Port * ip_port, char * data, uint32_t * length)
{
    ADDR addr;
    uint32_t addrlen = sizeof(addr);
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
        if(j == CLIENT_ID_SIZE)
        {
            //Refresh the client timestamp.
            list[i].timestamp = unix_time();
            return 1;
        }
    }
    return 0;
}

//check if client with client_id is already in node format list of length length.
//return True(1) or False(0)
int client_in_nodelist(Node_format * list, uint32_t length, char * client_id)
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
int get_close_nodes(char * client_id, Node_format * nodes_list)
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
//return 0 if successfull
//return 1 if not (list contains no bad nodes)
int replace_bad(Client_data * list, uint32_t length, char * client_id, IP_Port ip_port)
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
void addto_lists(IP_Port ip_port, char * client_id)
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
        if(!client_in_list(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id))
        {
            
            if(replace_bad(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id, ip_port))
            {
                //if we can't replace bad nodes we try replacing good ones
                replace_good(friends_list[i].client_list, MAX_FRIEND_CLIENTS, client_id, ip_port, self_client_id);
            }
            
        }  
    }
    
    
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
//returns 0 if problem.
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
    return 0;
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
    return 0;
}


//send a ping request
//Ping request only works if there is none hos been sent to that ip/port in the last 5 seconds.
int pingreq(IP_Port ip_port)
{
    if(is_pinging(ip_port))
    {
        return 1;
    }
    
    int ping_id = add_pinging(ip_port);
    if(ping_id == 0)
    {
        return 1;
    }
    
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
    
    int ping_id = add_gettingnodes(ip_port);
    
    if(ping_id == 0)
    {
        return 1;
    }
    
    char data[5 + CLIENT_ID_SIZE*2];
    data[0] = 2;
    
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    memcpy(data + 5 + CLIENT_ID_SIZE, client_id, CLIENT_ID_SIZE);

    return sendpacket(ip_port, data, sizeof(data));
}


//send a send nodes response
//Currently incomplete: missing bunch of stuff
int sendnodes(IP_Port ip_port, char * client_id, uint32_t ping_id)
{
   char data[5 + (CLIENT_ID_SIZE + sizeof(IP_Port))*MAX_SENT_NODES];
   Node_format nodes_list[MAX_SENT_NODES];
   
   int num_nodes = get_close_nodes(client_id, nodes_list);
   
   data[0] = 3;
   
   memcpy(data + 1, &ping_id, 4);
   memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
   memcpy(data + 5 + CLIENT_ID_SIZE, nodes_list, num_nodes * (CLIENT_ID_SIZE + sizeof(IP_Port)));
   
   return sendpacket(ip_port, data, 5 + CLIENT_ID_SIZE + num_nodes * (CLIENT_ID_SIZE + sizeof(IP_Port)));
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
    
    pingreq(source);
 
    return 0;
}

int handle_pingres(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE))
    {
        return 1;
    }
    
    addto_lists(source, packet + 5);
    return 0;
}

int handle_getnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE*2))
    {
        return 1;
    }
    uint32_t ping_id;
    memcpy(&ping_id, packet + 1, 4);
    sendnodes(source, packet + 5 + CLIENT_ID_SIZE, ping_id);
    
    pingreq(source);
    
    return 0;
}

int handle_sendnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length > 5 + MAX_SENT_NODES * (CLIENT_ID_SIZE + sizeof(IP_Port)) || 
    (length - 5) % (CLIENT_ID_SIZE + sizeof(IP_Port)) != 0)
    {
        return 1;
    } 
    int num_nodes = (length - 5) / (CLIENT_ID_SIZE + sizeof(IP_Port));
    uint32_t i;
    
    Node_format nodes_list[MAX_SENT_NODES];
    memcpy(nodes_list, packet + 5, num_nodes);
    
    for(i = 0; i < num_nodes; i++)
    {
        pingreq(nodes_list[i].ip_port);
    }
    
    addto_lists(source, packet + 5);
    return 0;
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




//TODO: Optimize this.
IP_Port getfriendip(char * client_id)
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
    
    



int DHT_recvpacket(char * packet, uint32_t length, IP_Port source)
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

//Ping each client in the "friends" list every 60 seconds.
//Send a get nodes request every 20 seconds to a random good node for each "friend" in our "friends" list.
void doFriends()
{
    uint32_t i, j;
    uint32_t temp_time = unix_time();
    for(i = 0; i < num_friends; i++)
    {
        for(j = 0; j < MAX_FRIEND_CLIENTS; j++)
        {
            if(friends_list[i].client_list[j].timestamp + Kill_NODE_TIMEOUT > temp_time)//if node is not dead.
            {
                //TODO: Make this better, it only works if the function is called more than once per second.
                if((temp_time - friends_list[i].client_list[j].timestamp) % PING_INTERVAL == 0)
                {
                    pingreq(friends_list[i].client_list[j].ip_port);
                }
                //TODO: Send getnodes requests
            }   
        }
    }
}


void doClose()
{
    uint32_t i;
    uint32_t temp_time = unix_time();
    for(i = 0; i < MAX_FRIEND_CLIENTS; i++)
    {
        if(close_clientlist[i].timestamp + Kill_NODE_TIMEOUT > temp_time)//if node is not dead.
        {
            //TODO: Make this better, it only works if the function is called more than once per second.
            if((temp_time - close_clientlist[i].timestamp) % PING_INTERVAL == 0)
            {
                pingreq(close_clientlist[i].ip_port);
            }
            //TODO: Send getnodes requests
        }   
    }    
}



void doDHT()
{
    doClose();
    doFriends();
}




void bootstrap(IP_Port ip_port)
{

    getnodes(ip_port, self_client_id);
    
}

