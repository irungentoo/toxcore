#include "DHT.h"


//Function to send packet(data) of length length to ip_port
int sendpacket(IP_Port ip_port, char * data, uint32_t length)
{
    ADDR addr = {.family = AF_INET, .ip = ip_port.ip, .port = ip_port.port};
    
    return sendto(sock, data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

//Compares client_id1 and client_id2 with client_id
//return 0 if both are same distance
//return 1 if client_id1 is closer.
//return 2 if client_id2 is closer.
int id_distance(char * client_id, char * client_id1, char * client_id2)
{
    int i;
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


//Attempt to add client with ip_port and client_id to the friends client list and close_clientlist
int addto_lists(IP_Port ip_port, char * client_id)
{
    
    
    
}


//send a ping request
//Currently incomplete: missing the ping_id part
int pingreq(IP_Port ip_port)
{
    char data[5 + CLIENT_ID_SIZE];
    data[0] = 0;
    
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    
    sendpacket(ip_port, data, sizeof(data));
    
}

//send a ping response
//Currently incomplete: missing the ping_id part
int pingres(IP_Port ip_port, uint32_t ping_id)
{
    char data[5 + CLIENT_ID_SIZE];
    data[0] = 1;
    
    memcpy(data + 1, &ping_id, 4);
    memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
    
    sendpacket(ip_port, data, sizeof(data));
    
}

//send a getnodes request
//Currently incomplete: missing the ping_id part
int getnodes(IP_Port ip_port, char * client_id)
{
   char data[5 + CLIENT_ID_SIZE*2];
   data[0] = 2;
   
   memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
   memcpy(data + 5 + CLIENT_ID_SIZE, client_id, CLIENT_ID_SIZE);
   
   sendpacket(ip_port, data, sizeof(data));
}

//send a getnodes request
//Currently incomplete: missing the ping_id part
int sendnodes(IP_Port ip_port, char * client_id)
{
   char data[5 + (CLIENT_ID_SIZE + 6)*8];
   data[0] = 3;
   
   memcpy(data + 5, self_client_id, CLIENT_ID_SIZE);
   memcpy(data + 5 + CLIENT_ID_SIZE, client_id, CLIENT_ID_SIZE);
   
   sendpacket(ip_port, data, sizeof(data));
}




//Packet handling functions
//One to handle each types of packets

int handle_pingreq(char * packet, uint32_t length, IP_Port source)
{
    if(length != 5 + CLIENT_ID_SIZE)
    {
        return 1;
    }
    
    uint32_t ping_id;
    
    memcpy(&ping_id, packet + 1, 4);
    pingres(source, ping_id);
    
    addto_lists(source, packet + 5);
    
    return 0;
}

int handle_pingres(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE))
    {
        return 1;
    }
    
    
}

int handle_getnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length != (5 + CLIENT_ID_SIZE*2))
    {
        return 1;
    }
    
    
    addto_lists(source, packet + 5);
    
    return 0;   
}

int handle_sendnodes(char * packet, uint32_t length, IP_Port source)
{
    if(length > 325 || (length - 5) % (CLIENT_ID_SIZE + 6) != 0)
    {
        return 1;
    } 
    
    
}





void addfriend(char * client_id)
{
    
    
    
    
}





char delfriend(char * client_id)
{
    
    
    
    
}





IP_Port getfriendip(char * client_id)
{
    
    
    
}




void DHT_recvpacket(char * packet, uint32_t length, IP_Port source)
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
        return;
        
    }
    

}





void doDHT()
{
    
    
    
}




void bootstrap(IP_Port ip_port)
{

    getnodes(ip_port, self_client_id);
    
}

