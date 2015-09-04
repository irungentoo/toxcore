## General
The Tox profile data file is a simple binary format and the general structure looks as follows:
- **4 zero bytes** at the start of the file.
- **4 byte unsigned integer** that has a value of **'MESSENGER_STATE_COOKIE_GLOBAL'**. This should be used to check to see whether or not this is a Tox profile data file.
- A list of sections.
- **4 byte unsigned integer** with a value of 255. This indicates that the end of the data file has been reached.

## Section structures
Every section has the following general structure:
- **4 byte unsigned integer** that contains the state type.
- **4 byte unsigned integer** that contains the 'length' of the rest of this section.
- **'length' bytes** of data that contain the structure of this section.

A list of the state types:

Name          | Value | Type
------------- | ----- | --------
NospamKeys    | 1     | uint16_t
Dht           | 2     | uint16_t
Friends       | 3     | uint16_t
Name          | 4     | uint16_t
StatusMessage | 5     | uint16_t
Status        | 6     | uint16_t
TcpRelay      | 10    | uint16_t
PathNode      | 11    | uint16_t

### NospamKeys
- **4 byte unsigned integer** that contains the nospam.
- **32 bytes** that contain the public key.
- **32 bytes** that contain the secret key.

### Dht
This section contains a list DHT related sections. The list of DHT state types is as follows:

Name  | Value | Type
----- | ----- | --------
Nodes | 4     | uint16_t

The general structure of the DHT section looks as follows:
- **4 byte unsigned integer** that has a value of **'DHT_STATE_COOKIE_GLOBAL'**.
- A list of sections.

Every DHT section has the following structure:
- **4 byte unsigned integer** that contains the 'length' if this section.
- **4 byte unsigned integer** that contains the state type of this section.
- **'length' bytes** of data that contain the structure of this section.

#### Nodes
This section contains a list of nodes that toxcore has saved. The structure is as follows:
- List of nodes. The structure of these nodes is the same as PathNodes.

### Friends
This is a list of the friends that are in this data file. Every friend has a fixed size and has the following structure:
- **1 byte** that indicates whether or not we should send a friend request to this friend.
- **32 bytes** that contain the public key.
- **1024 bytes** that contain the friend request message.
- **2 byte unsigned integer** that contains the size of the friend request message.
- **128 bytes** that contain the name.
- **2 byte unsigned integer** that contains the lenght of the name.
- **1007 bytes** that contain the status message.
- **2 byte unsigned integer** that contains the status message.
- **1 byte unsigned integer** that contains the user status.
- **4 byte unsigned integer** that contains the nospam that was received with the friend request.
- **8 byte unsigned integer** that contains the time at which we last received a ping from this friend.

### Name
This section contains the name of the user
- **'length' bytes** that contain a UTF-8 encoded string.

### StatusMessage
This section contains the status message of the user
- **'length' bytes** that contain a UTF-8 encoded string.

### Status
- **1 byte** that contains the user status.

### TcpRelay
This section contains a list of TCP relays that toxcore has saved. The structure is exactly the same as PathNodes.

### PathNode
This section contains a list of path nodes that toxcore has saved.

These nodes have the following structure:
- **1 byte unsigned integer** that represents the family of the IP address that follows. These are the possible values:

Name          | Value | Family
------------- | ----- | ------
TOX_AF_INET   | 2     | IPv4
TOX_AF_INET6  | 10    | IPv6
TOX_TCP_INET  | 130   | IPv4
TOX_TCP_INET6 | 138   | IPv6

- If the address family is IPv4, this space takes up **4 bytes** that contain an IPv4 address. If the address family is IPv6, this space takes up **16 bytes** that contain an IPv6 address.
- **2 byte unsigned integer** that contains the port.
- **32 bytes** that contain the public key of the node.

## Obtaining the state type of a section
In the following code example, state_type should be the 4 byte unsigned integer that is designated as the state type in the data file and cookie_inner should be MESSENGER_STATE_COOKIE_TYPE or DHT_STATE_COOKIE_TYPE depending on which section you're in.

```c
bool get_state_type(uint32_t state_type, uint32_t cookie_inner, uint16_t *state)
{
  if (state_type >> 16 != cookie_inner) {
    return 0;
  }

  *state = state_type & 0xFFFF;
  return 1;
}
```

Here is a list of constants regarding cookies:

Name                          | Value      | Type
----------------------------- | ---------- | --------
MESSENGER_STATE_COOKIE_GLOBAL | 0x15ED1B1F | uint32_t
MESSENGER_STATE_COOKIE_TYPE   | 0x01CE     | uint32_t
DHT_STATE_COOKIE_GLOBAL       | 0x159000D  | uint32_t
DHT_STATE_COOKIE_TYPE         | 0x11CE     | uint32_t
