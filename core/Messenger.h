/* Messenger.h
* 
* An implementation of a simple text chat only messenger on the tox network core.
* 
*/
 
 
#ifndef MESSENGER_H 
#define MESSENGER_H  

#include "net_crypto.h"
#include "DHT.h"


//add a friend
//returns the friend number if success
//return -1 if failure.
int m_addfriend(uint8_t * client_id);


//remove a friend
int m_delfriend(int friendnumber);

//return 1 if friend is online
//return 0 if he is not
int m_friendonline(int friendnumber);


//send a text chat message to a friend.
int m_sendmessage(int friendnumber);


//set the function that will be executed when a friend request is recieved.
int m_callback_friendrequest();


//set the function that will be executed when a message from a friend is recieved.
int m_callback_friendmessage();


//run this at startup
void initMessenger();


//the main loop that needs to be run at least 200 times per second.
void doMessenger();

#endif
