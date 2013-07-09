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
int m_friendstatus(int friendnumber);


//send a text chat message to a friend.
int m_sendmessage(int friendnumber, uint8_t * message, uint32_t length);

//set the data that will be sent along with friend requests
//return -1 if failure
//return 0 if success
int m_setinfo(uint8_t * data, uint16_t length);

//set the function that will be executed when a friend request is received.
//function format is function(uint8_t * public_key, uint8_t * data, uint16_t length)
int m_callback_friendrequest(void (*function)(uint8_t *, uint8_t *, uint16_t));


//set the function that will be executed when a message from a friend is received.
//function format is: function(int friendnumber, uint8_t * message, uint32_t length)
int m_callback_friendmessage(void (*function)(int, uint8_t *, uint16_t));


//run this at startup
void initMessenger();


//the main loop that needs to be run at least 200 times per second.
void doMessenger();

#endif
