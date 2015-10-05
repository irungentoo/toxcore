# Group Chats
This document details the groupchat implementation, giving a high level overview of all the important features and aspects, as well as some important low level implementation details. This documentation reflects what is currently implemented at the time of writing; it is not speculative. For detailed API docs see the groupchats section of the tox.h header file.

## Index
- [Features](#Features)
- [Group roles](#Group roles)
- [Group types](#Group types)
  - [Public](#Public)
  - [Private](#Private)
- [Cryptography](#Cryptography)
  - [Permanent keypairs](#Permanent keypairs)
  - [Session keypair](#Session keypair)
  - [Group keypairs](#Group keypairs)
  - [DHT keypair](#DHT keypair)
- [Founders](#Founders)
  - [Shared state](#Shared state)
- [Moderation](#Moderation)
  - [Kicks/bans](#Kicks/bans)
  - [Moderator list](#Moderator list)
  - [Sanctions list](#Sanctions list)
- [Topics](#Topics)
- [State syncing](#State syncing)
- [Group syncing](#Group syncing)
- [DHT Announcements](#DHT Announcements)
  - [Announcement requests](#Announcement requests)
  - [Get nodes requests](#Get nodes requests)
  - [Redundancy](#Redundancy)

<a name="Features" />
## Features
* Private messages
* Action messages (/me)
* Public groups (peers may join via a public key)
* Private groups (peers require a friend invite)
* Permanence (a group cannot 'die' as long as at least one peer retains their group credentials)
* Persistence across client restarts
* Ability to set peer limits
* Moderation (kicking, banning, silencing)
* Permanent group names (set on creation)
* Topics (may only be set by moderators and the founder)
* Password protection
* Self-repairing (auto-rejoin on disconnect, group split protection, state syncing)
* Identity separation from the Tox ID
* Ability to ignore peers
* Unique nicknames which can be set on a per-group basis
* Peer statuses (online, away, busy) which can be set on a per-group basis
* Custom parting/exit messages

<a name="Group roles" />
## Group roles
There are four distinct roles which are hierarchical in nature (higher roles have all the privileges of lower roles).

* **Founder** - The group's creator. May set all other peers roles to anything except founder. May also set the group password, toggle the privacy state, and set the peer limit.
* **Moderator** - Promoted by the founder. May kick, ban and set the user and observer roles for peers below this role. May also set the topic.
* **User** - Default non-founder role. May communicate with other peers normally.
* **Observer** - Demoted by moderators and the founder. May observe the group and ignore peers; may not communicate with other peers or with the group.

<a name="Group types" />
## Group types
Groups can have two types: private and public. The type can be set on creation, and may also be toggled by the group founder at any point after creation. (_Note: password protection is completely independent of the group type_)

<a name="Public" />
### Public
Anyone may join the group using the Chat ID. If the group is public, information about peers inside the group, including their IP addresses and group public keys (but not their Tox ID's) is visible to anyone with access to a node storing their DHT announcement. See the [DHT Announcements](#DHT Announcements) section for details.

<a name="Private" />
### Private
The only way to join a private group is by having someone in your friend list send you an invite. If the group is private, no peer/group information (mentioned in the Public section) is present in the DHT; the DHT is not used for any purpose at all. If a public group is set to private, all DHT information related to the group will expire within a few minutes.

<a name="Cryptography" />
## Cryptography
Groupchats use the [NaCl/libsodium cryptography library](https://en.wikipedia.org/wiki/NaCl_(software)) for all cryptography related operations. All group communication is end-to-end encrypted. Message confidentiality, integrity, and repudability are guaranteed via [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption), and [perfect forward secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) is also provided.

One of the most important security improvements from the old groupchat implementation is the removal of a message-relay mechanism that uses a group-wide shared key. Instead, connections are 1-to-1 (a complete graph), meaning an outbound message is sent once per peer, and encrypted/decrypted using a key unique to each peer. This prevents MITM attacks that were previously possible. This additionally ensures that private messages are truly private.

Groups make use of 13 unique keys in total: Two permanent keypairs (encryption and signature), two group keypairs (encryption and signature), one session keypair (encryption), one shared symmetric key (encryption), and one temp DHT keypair (encryption).

The Tox ID/Tox public key is not used for any purpose. As such, neither peers in a given group nor in the group DHT can be matched with their Tox ID. In other words, there is no way of identifying a peer aside from their IP address, nickname, and group public key. (_Note: group nicknames can be different from the client's main nickname that their friends see_).

<a name="Permanent keypairs" />
### Permanent keypairs
When a peer creates or joins a group they generate two permanent keypairs: an encryption keypair and a signature keypair, both of which are unique to the group. The two public keys are the only guaranteed way to identify a peer, and both keypairs will persist for as long as a peer remains in the group (even across client restarts). If a peer exits the group these keypairs will be lost forever.

This encryption keypair is not used for any encryption operations except for the initial handshake when connecting to another peer. For usage details on the signature key, see the [Moderation](#Moderation) section.

<a name="Session keypair" />
### Session keypair/shared symmetric key
When two peers establish a connection they each generate a session encryption keypair and share one another's resulting public key. With their own session secret key and the other's session public key, they will both generate the same symmetric encryption key. This symmetric key will be used for all further encryption operations between them for the current session (i.e. until one of them disconnects).

The purpose of this extra key exchange is to prevent an adversary from decrypting messages from previous sessions in event that a secret encryption key becomes compromised. This is known as forward secrecy.

<a name="Group keypairs" />
### Group keypairs
The group founder generates two additional permanent keypairs when the group is created: an encryption keypair, and a signature keypair. The public signature key is considered the **Chat ID** and is used as the group's permanent identifier, allowing other peers to join public groups via the DHT. Every peer in the group holds a copy of the group's public encryption key along with the public signature key/Chat ID.

The group secret keys are similar to the permanent keypairs in that they will persist across client restarts, but will be lost forever if the founder exits the group. This is particularly important as administration related functionality will not work without these keys. See the [Founders](#Founders) section for usage details.

<a name="DHT keypair" />
### Temporary DHT keypair
All group related DHT procedures make use of toxcore's temp DHT keypair. This keypair is generated when the Tox object is initialized and does not persist across client restarts. See the [DHT Announcements](#DHT Announcements) section for further details.

<a name="Founders" />
## Founders
The peer who creates the group is the group's founder. Founders have a set of admin privileges, including:
* Promoting and demoting moderators
* The ability to kick/ban moderators
* Setting the peer limit
* Setting the group's privacy state
* Setting group passwords

<a name="Shared state" />
### Shared state
Groups contain a data structure called the **shared state** which is given to every peer who joins the group. In this structure resides all data pertaining to the group that must only be modifiable by the group founder. This includes things like the group name, the group type, the peer limit, and the password. Additionally, the shared state holds a copy of the group founder's public encryption and signature keys, which is how other peers in the group are able to verify the identity of the group founder.

The shared state is signed by the founder using the group secret signature key. As the founder is the only peer who holds this secret key, this ensures that the shared state may be safely shared by untrusted peers, even in the absence of the founder.

When the founder modifies the shared state, he increments the shared state version, signs the new shared state data with the group secret signature key, and broadcasts the new shared state data along with its signature to the entire group. When a peer receives this broadcast, he uses the group public signature key to verify that the data was signed with the group secret signature key, and also verifies that the new version is not older than the current version.

<a name="Moderation" />
## Moderation
The founder has the ability to promote other peers to the moderator role. Moderators have all the privileges of normal users, and additionally have the power to kick, ban, and unban, as well as give peers below the moderator role the roles of user and observer (see the [Group roles](#Group roles) section). Moderators can also modify the group topic. Moderators have no power over one another; only the founder can kick, ban, or change the role of a moderator.

<a name="Kicks/bans" />
### Kicks/bans
When a peer is kicked or banned from the group, his chat instance and all its associated data will be destroyed. This includes all public and secret keys. Additionally, the the peer will not receive any notifiactions; it will simply appear to them as if the group is inactive.

<a name="Moderator list" />
### Moderator list
Each peer holds a copy of the **moderator list**, which is an array of public signature keys of peers who currently have the moderator role (including those who are offline). A hash (sha256) of this list called the **mod_list_hash** is stored in the shared state, which is itself signed by the founder using the group secret signature key. This allows the moderator list to be shared between untrusted peers, even in the absence of the founder, while maintaining moderator verifiability.

When the founder modifies the moderator list, he updates the mod_list_hash, increments the shared state version, signs the new shared state, broadcasts the new shared state data along with its signature to the entire group, then broadcasts the new moderator list to the entire group. When a peer receives this moderator list (having already verified the new shared state), he creates a hash of the new list and verifies that it is identical to the mod_list_hash.

<a name="Sanctions list" />
### Sanctions list
Each peer holds a copy of the **sanctions list**. This list holds two sublists: Banned peers, and peers with the observer role, or the **ban list** and the **observer list** respectively. The ban list contains entries of peers who have been banned, including their last used nickname, IP address/port, and a unique ID. The sanctions list contains entries of peers who have been demoted to the observer role, including just their public encryption key.

All entries additionally contain a timestamp of the time the entry was made, the public signature key of the peer who set the sanction, and a signature of the entry's data, which is signed by the peer who created the entry using their secret signature key. Individual entries are verified by ensuring that the entry's public signature key belongs to the founder or is present in the moderator list, and then verifying that the entry's data was signed by the owner of that key.

Although each individual entry can be verified, we still need a way to verify that the list as a whole is complete and identical for every peer, otherwise any peer would be able to remove entries arbitrarily, or replace the list with an older version. Therefore each peer holds a copy of the **sanctions list credentials**. This is a data structure that holds the version, a hash (sha256) of all sanctions list entries plus the version, the public signature key of the last peer to have modified the sanctions list, and a signature of the hash, which is created by that key.

When a moderator or founder modifies the sanctions list, he will increment the version, create a new hash, sign the hash+version with his secret signature key, and replace the old public signature key with his own. He will then broadcast the new changes (not the entire list) to the entire group along with the new credentials. When a peer receives this broadcast, he will verify that the new credentials version is not older than the current version and verify that the changes were made by a moderator or the founder. If adding an entry, he will verify that the entry was signed by the signature key of the entry's creator.

When the founder kicks, bans or demotes a moderator, he will first go through the sanctions list and re-sign each entry made by that moderator with his own founder key, then re-broadcast the sanctions list to the entire group. This is necessary to guarantee that all sanctions list entries and its credentials are signed by a current moderator or the founder at all times.

_Note: The sanctions list is not saved to the Tox save file, meaning that if the group ever becomes empty, the sanctions list will be reset. This is in contrast to the shared state and moderator list, which are both saved and will persist even if the group becomes empty._

<a name="Topics" />
## Topics
Founders and moderators have the ability to set the **topic**, which is simply an arbitrary string of characters. The integrity of a topic is maintained in a similar manner as sanctions entries, using a data structure called **topic_info**. This is a struct which contains the topic, a version, and the public key of the peer who set it.

When a peer modifies the topic, they will increment the version, sign the new topic+version with their secret signature key, replace the public key with their own, then broadcast the new topic_info data along with the signature to the entire group. When a peer receives this broadcast, they will first check if the public signature key of the setter either belongs to the founder, or is in the moderator list. They will then verify the signature using the setter's public signature key, and finally they will ensure that the version is not older than the current topic version.

If the moderator who set the current topic is kicked, banned, or demoted, the founder will re-sign the topic using his own signature key, and rebroadcast it to the entire group.

<a name="State syncing" />
## State syncing
Peers send four unsigned 32-bit integers along with their ping packets: Their peer count[1], their shared state version, their sanctions credentials version, and their topic version. If a peer receives a ping in which any of these values are greater than their own, this indicates that they may be out of sync with the rest of the group. In this case they will do one of two things: If they already have a sync request flagged for this peer, they will send a sync request. Otherwise they will set the flag and wait until the next ping arrives (this waiting is to correct for false-positives in the case of high network latency). The flag is reset after a sync request is sent, or whenever a ping is received in which all data is in sync.

[1] We use a "real" peer count, which is the number of confirmed peers in the peerlist (that is, peers who you have successfully handshaked and exchanged peer info with).

<a name="Group syncing" />
## Group syncing
In order to prevent entirely separate subgroups with the same Chat ID from being created, be it due to network issues or a malicious MITM attempt, it's necessary for groups to periodically search the DHT for announced nodes that match the group's Chat ID but are not present in the group. In case an unknown node is found, an attempt will be made to connect with it. If successful, the state sync mechanism will merge the subgroups shortly.

Since we don't want to spam the DHT with a redundant number of requests that grows linearly with the size of the group, peers will take turns doing the search. Peers decide independently if it's their turn to search. Each peer has the same base timer T, and every interval of T they will do a search with a probability P which is inversely proportionate to the number of peers N. For example, if N=1 then P=1.0. If N=4 then P=0.25. If N=100 then P=0.01 and so on. This guarantees that a given group will do 1 search per T interval on average regardless of its size, and it also ensures that a full spectrum of the network is searched. Moreover, because peers act independently rather than in coordination, malicious peers have little exploit potential (e.g. attempting to stop the group from searching the DHT).

In addition, peers who join a group via the DHT will attempt to connect to any nodes that are not in their freshly synced peer list.

<a name="DHT Announcements" />
## DHT Announcements
Groupchats make use of the Tox DHT network in order to allow for groups that can be joined by anyone who possesses the Chat ID. As all of the information stored in or passed through the DHT can be viewed by any of the involved nodes, these types of groups are considered to be public. Private groups in contrast do not make use of the DHT for any purpose, and as such require a friend invite in order to join.

<a name="Announcement requests" />
### Announcement requests
When peers create or successfully join a public group they send an **announcement request**, containing information about the group that they're announcing and themselves to K of their close DHT nodes. The information in this request includes the announcer's group public encryption key and IP address/port, as well as the Chat ID of the group. The DHT attempts to store this announcement in the node that's closest to the Chat ID (**closeness** is calculated by the DHT's close function). DHT nodes can store up to N announcements each, after which they will replace the oldest announcements first. See the [Redundancy](#Redundancy) section for details on how DDOS attacks are mitigated.

<a name="Get nodes requests" />
### Get nodes requests
When peers attempt to join a public group using the Chat ID they send a **get nodes request**, containing their IP/port, their group public encryption key, and the Chat ID to K of their close nodes. Those nodes will then check if any of their announcement entries match the supplied Chat ID. If not, they will relay the message to K of their own close nodes who will repeat the process (note that the close function guarantees that each successive relay will bring us closer to the Chat ID until we either find one of its entries, or have traversed the entire DHT network).

Once a node finds an entry with the queried Chat ID it will send a **send nodes response** to the original node who made the request. The response will contain at least one entry (possibly more) which will hold the group public encryption key and the IP address/port of a peer who had previously made an announcement request for Chat ID. With this information the requester will automatically initiate the handshake protocol and attempt to join the group.

<a name="Redundancy" />
### Redundancy
DHT nodes will send ping requests to all of their announcement entries periodically in order to ensure that they are still present in the network/group. When a peer goes offline or leaves a group, they no longer respond to these ping requests, and the nodes holding their entries will discard them.

There are scenarios in which an announcement may be dropped from the network, such as if the sole node holding the entry goes offline, or in the case of DDOS attack which attempts to push all old entries out of the DHT. In order to ensure that those announcements are not permanently lost, announcers will periodically check when they last received a ping request for a given announcement. After a certain amount of time without receiving a ping request they will assume that their entry is no longer in the DHT network and re-announce themselves. This ensures that every peer present in a group has an active announcement in the DHT at all times, and it also ensures that a group cannot become 'lost'.
