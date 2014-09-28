# User avatars in Tox



## Introduction and rationale

User avatars are small icons or images used to identify users in the friend
list; they exists in virtually all VoIP and IM protocols and provide an easy
way to an user identify another in the friend list.

This document describes the implementation of avatars in the Tox protocol,
according to the following design considerations:

  - Avatars are handled as private information, ie., only exchanged over
    Tox encrypted channels among previously authenticated friends;

  - The library treats all images as blobs and does not interpret or
    understands image formats, only ensures that the avatar data sent by
    an user is correctly received by the other. The client application is
    responsible for validating, decoding, resizing, and presenting the
    image to the user.

  - There is a strict limit of 16 KiB to the avatar raw data size -- this
    seems suitable for practical use as, for example, the raw data of an
    uncompressed 64 x 64 pixels 24 bpp RGB bitmap is 12288 bytes long; the
    data limit provides enough space for larger bitmaps if the usual
    compressed formats are used.

    **Notice:** As designed, this limit can be changed in the future without
    breaking the protocol compatibility, but clients using the original
    limit will reject larger avatars;

  - The protocol MUST provide means to allow caching and avoid unnecessary
    data transfers;

  - Avatars are transfered between clients in a background operation;

  - Avatars are served in a "best effort" basis, without breaking clients
    who do not support them;

  - The protocol MUST resist to malicious users;

  - The protocol MUST work with both UDP and TCP networks.


The Single Tox Standard Draft v.0.1.0 recommends implementing avatars as
a purely client-side feature through a procedure that can be summarized as
sending a specially named file as a file transfer request and accepting
it silently. This procedure can be improved to provide the previously stated
design considerations, but this requires a higher integration with the core
protocol. Moving this feature to the core protocol also:

  - Provides a simpler and cleaner interfaces for client applications;

  - Hides protocol complexities from the client;

  - Avoids code duplication and ad-hoc protocols in the clients;

  - Avoids incompatibility between client implementations;

  - Allows important optimizations such as lightweight notification of
    removed and updated avatars;

  - Plays well with cache schemes;

  - Makes avatar transfer an essentially background operation.






## High level description

The avatar exchange is implemented with the following new elements in the
Tox protocol. This is a very high level description and the usage patterns
expected from client applications are described in Section "Using Avatars
in Client Applications" and a low level protocol description is available
in Section "Internal Protocol Description".

  - **Avatar Information Notifications** are events which may be sent by
    an user to another anytime, but are usually sent after one of them
    connects to the network, changes his avatar, or in reply to an **avatar
    information request**. They are delivered by a very lightweight message
    but with information enough to allow an user to validate or discard an
    avatar from the local cache and decide if is interesting to request the
    avatar data from the peer.

    This event contain two data fields: (1) the image format and (2) the
    cryptographic hash of the actual image data. Image format may be NONE
    (for users who have no avatar or removed their avatars) or PNG. The
    cryptographic hash is intended to be compared with the hash o the
    currently cached avatar (if any) and check if it stills up to date.

  - **Avatar Information Requests** are very lightweight messages sent by an
    user asking for an **avatar information notification**. They may be sent
    as part of the login process or when the client thinks the currently
    cached avatar is outdated. The receiver may or may not answer to this
    request. This message contains no data fields;

  - An **Avatar Data Request** is sent by an user asking another for his
    complete avatar data. It is sent only when the requesting user decides
    the avatar do not exists in the local cache or is outdated. The receiver
    may or may not answer to this request. This message contains no data
    fields.

  - An **Avatar Data Notification** is an event signaling the client that
    the complete avatar image data of another user is available. The actual
    data transfer is implemented using several data and control messages,
    but the details are hidden from the client applications. This event can
    only arrive in reply to an **avatar data request**.

    This event contains three data fields: (1) the image format, (2) the
    cryptographic hash of the image data, and (3) the raw image data. If the
    image format is NONE (i.e. no avatar) the hash is zeroed and the image
    data is empty. The raw image data is locally validated and ensured to
    match the hash (the event is **not** triggered otherwise).





## API

To implement this feature, the following public symbols were added. The
complete API documentation is available in `tox.h`.


```
#define TOX_AVATAR_MAX_DATA_LENGTH 16384
#define TOX_HASH_LENGTH 32


/* Data formats for user avatar images */
typedef enum {
    TOX_AVATAR_FORMAT_NONE,
    TOX_AVATAR_FORMAT_PNG
}
TOX_AVATAR_FORMAT;



/* Set the user avatar image data. */
int tox_set_avatar(Tox *tox, uint8_t format, const uint8_t *data, uint32_t length);

/* Get avatar data from the current user. */
int tox_get_self_avatar(const Tox *tox, uint8_t *format, uint8_t *buf, uint32_t *length, uint32_t maxlen, uint8_t *hash);

/* Generates a cryptographic hash of the given data (usually a cached avatar). */
int tox_hash(uint8_t *hash, const uint8_t *data, const uint32_t datalen);

/* Request avatar information from a friend. */
int tox_request_avatar_info(const Tox *tox, const int32_t friendnumber);

/* Send an unrequested avatar information to a friend. */
int tox_send_avatar_info(Tox *tox, const int32_t friendnumber);

/* Request the avatar data from a friend. */
int tox_request_avatar_data(const Tox *tox, const int32_t friendnumber);

/* Set the callback function for avatar data. */
void tox_callback_avatar_info(Tox *tox, void (*function)(Tox *tox, int32_t, uint8_t, uint8_t*, void *), void *userdata);

/* Set the callback function for avatar data.  */
void tox_callback_avatar_data(Tox *tox, void (*function)(Tox *tox, int32_t, uint8_t, uint8_t*, uint8_t*, uint32_t, void *), void *userdata);
```




## Using Avatars in Client Applications


### General recommendations

  - Clients MUST NOT imply the availability of avatars in other users.
    Avatars are an optional feature and not all users and clients may
    support them;

  - Clients MUST NOT block waiting for avatar information and avatar data
    packets;

  - Clients MUST treat avatar data as insecure and potentially malicious;
    For example, users may accidentally use corrupted images as avatars,
    a malicious user may send a specially crafted image to exploit a know
    vulnerability in an image decoding library, etc. It is recommended to
    handle the avatar image data in the same way as an image downloaded
    from an unknown Internet source;

  - The peers MUST NOT assume any coupling between the operations of
    receiving an avatar information packet, sending unrequested avatar
    information packets, requesting avatar data, or receiving avatar data.

    For example, the following situations are valid:

      * A text-mode client may send avatars to other users, but never
        request them;

      * A client may not understand a particular image format and ignore
        avatars using it, but request and handle other formats;

  - Clients SHOULD implement a local cache of avatars and do not request
    avatar data from other peers unless necessary;

  - When an avatar information is received, the client should delete the
    avatar if the new avatar format is NONE or compare the hash received
    from the peer with the hash of the currently cached avatar. If they
    differ, send an avatar data request;

  - If the cached avatar is older than a given threshold, the client may
    also send an avatar info request to that friend once he is online and
    mark the avatar as updated *before* any avatar information is received
    (to not spam the peer with such requests);

  - When an avatar data notification is received, the client must update
    the cached avatar with the new one;

  - Clients should resize or crop the image to the way it better adapts
    to the client user interface;

  - If the user already have an avatar defined in the client configuration,
    it must be set before connecting to the network to avoid spurious avatar
    change notifications and unnecessary data transfers.

  - If no avatar data is available for a given friend, the client should
    show a placeholder image.



### Interoperability and sharing avatars among different clients

**This section is a tentative recommendation of how clients should store
avatars to ensure local interoperability and should be revised if this
code is accepted into Tox core.**

It is desirable that the user avatar and the cached friends avatars could be
shared among different Tox clients in the same system, in the spirit of the
proposed Single Tox Standard. This not only makes switching from one client
to another easier, but also minimizes the need of data transfers, as avatars
already downloaded by other clients can be reused.

Given the Tox data directory described in STS Draft v0.1.0:

  - The user avatar is stored in a file named "avatar.png". As more formats
    may be used in the future, another extensions are reserved and clients
    should keep just one file named "avatar.*", with the data of the last
    avatar set by the user. If the user have no avatar, no such files should
    be kept in the data directory;

  - Friends avatars are stored in a directory called "avatars" and named
    as "xxxxx.png", where "xxxxx" is the complete client id encoded as an
    uppercase hexadecimal string and "png" is the extension for the PNG
    avatar. As new image formats may be used in the future, clients should
    ensure no other file "xxxxx.*" exists. No file should be kept for an user
    who have no avatar.

    **To be discussed:** User keys are usually presented in Tox clients as
    upper case strings, but lower case file names are more usual.


Example for Linux and other Unix systems, assuming an user called "gildor":

    Tox data directory: /home/gildor/.config/tox/
    Tox data file:      /home/gildor/.config/tox/data
    Gildor's avatar:    /home/gildor/.config/tox/avatar.png
    Avatar data dir:    /home/gildor/.config/tox/avatars/
    Elrond's avatar:    /home/gildor/.config/tox/avatars/43656C65627269616E20646F6E277420546F782E426164206D656D6F72696573.png
    Elladan's avatar:   /home/gildor/.config/tox/avatars/49486174655768656E48756D616E735468696E6B49416D4D7942726F74686572.png
    Elrohir's avatar    /home/gildor/.config/tox/avatars/726568746F7242794D6D41496B6E696854736E616D75486E6568576574614849.png
    Arwen's avatar:     /home/gildor/.config/tox/avatars/53686520746F6F6B20476C6F7266696E64656C277320706C6163652068657265.png
    Lindir's avatar:    /home/gildor/.config/tox/avatars/417070735772697474656E42794D6F7274616C734C6F6F6B54686553616D652E.png

This recommendation is partially implemented by "testing/test_avatars.c".





### Common operations

These are minimal examples of how perform common operations with avatar
functions. For a complete, working, example, see `testing/test_avatars.c`.


#### Setting an avatar for the current user

In this example `load_data_file` is just an hypothetical function that loads
data from a file into the buffer and sets the length accordingly.

    uint8_t buf[TOX_AVATAR_MAX_DATA_LENGTH];
    uint32_t len;

    if (load_data_file("avatar.png", buf, &len) == 0)
        if (tox_set_avatar(tox, TOX_AVATAR_FORMAT_PNG, buf, len) != 0)
            fprintf(stderr, "Failed to set avatar.\n");

If the user is connected, this function will also notify all connected
friends about the avatar change.

If the user already have an avatar defined in the client configuration, it
must be set before connecting to the network to avoid spurious avatar change
notifications and unnecessary data transfers.




#### Removing the avatar from the current user

To remove an avatar, an application must set it to `TOX_AVATAR_FORMAT_NONE`.

    tox_set_avatar(tox, TOX_AVATAR_FORMAT_NONE, NULL, 0);

If the user is connected, this function will also notify all connected
friends about the avatar change.





#### Receiving avatar information from friends

All avatar information is passed to a callback function with the prototype:

    void function(Tox *tox, int32_t friendnumber, uint8_t format,
        uint8_t *hash, uint8_t *data, uint32_t datalen, void *userdata)

As in this example:

    static void avatar_info_cb(Tox *tox, int32_t friendnumber, uint8_t format,
            uint8_t *hash, void *userdata)
    {
        printf("Receiving avatar information from friend %d. Format = %d\n",
            friendnumber, format);
        printf("Data hash: ");
        hex_printf(hash, TOX_HASH_LENGTH);   /* Hypothetical function */
        printf("\n");
    }

And, somewhere in the Tox initialization calls, set if as the callback to be
triggered when an avatar information event arrives:

    tox_callback_avatar_info(tox, avatar_info_cb, NULL);


A typical client will test the currently cached avatar against the hash given
in the avatar information event and, if needed, request the avatar data.



#### Receiving avatar data from friends

Avatar data events are only delivered in reply of avatar data requests which
**should** only be sent after getting the user avatar information (format
and hash) from an avatar information event and checking it against a local
cache.

For this, an application must define an avatar information callback which
checks the local avatar cache and emits an avatar data request if necessary:

    static void avatar_info_cb(Tox *tox, int32_t friendnumber, uint8_t format,
            uint8_t *hash, void *userdata)
    {
        printf("Receiving avatar information from friend %d. Format = %d\n",
            friendnumber, format);
        if (format = TOX_AVATAR_FORMAT_NONE) {
            /* User have no avatar or removed the avatar */
            delete_avatar_from_cache(tox, friendnumber);
        } else {
            /* Use the received hash to check if the cached avatar is
               still updated. */
            if (!is_user_cached_avatar_updated(tox, friendnumber, hash)) {
                /* User avatar is outdated, send data request */
                tox_request_avatar_data(tox, friendnumber);
            }
        }
    }


Then define an avatar data callback to store the received data in the local
cache:

    static void avatar_data_cb(Tox *tox, int32_t friendnumber, uint8_t format,
        uint8_t *hash, uint8_t *data, uint32_t datalen, void *userdata)
    {
        if (format = TOX_AVATAR_FORMAT_NONE) {
            /* User have no avatar or removed the avatar */
            delete_avatar_from_cache(tox, friendnumber);
        } else {
            save_avatar_data_to_cache(tox, friendnumber, format, hash,
                data, datalen);
        }
    }


And, finally, register both callbacks somewhere in the Tox initialization
calls:

    tox_callback_avatar_info(tox, avatar_info_cb, NULL);
    tox_callback_avatar_data(tox, avatar_data_cb, NULL);


In the previous examples, implementation of the functions to check, store
and retrieve data from the cache were omitted for brevity. These functions
will also need to get the friend client ID (public key) from they friend
number and, usually, convert it from a byte string to a hexadecimal
string. A complete, yet more complex, example is available in the file
`testing/test_avatars.c`.











## Internal Protocol Description

### New packet types

The avatar transfer protocol adds the following new packet types and ids:

    PACKET_ID_AVATAR_INFO_REQ = 52
    PACKET_ID_AVATAR_INFO = 53
    PACKET_ID_AVATAR_DATA_CONTROL = 54
    PACKET_ID_AVATAR_DATA_START = 55
    PACKET_ID_AVATAR_DATA_PUSH = 56




### Requesting avatar information

To request avatar information, an user must send a packet of type
`PACKET_ID_AVATAR_INFO_REQ`. This packet have no data fields. Upon
receiving this packet, a client which supports avatars should answer with
a `PACKET_ID_AVATAR_INFO`. The sender must accept that the friend may
not answer at all.




### Receiving avatar information

Avatar information arrives in a packet of type `PACKET_ID_AVATAR_INFO` with
the following structure:

    PACKET_ID_AVATAR_INFO (53)
    Packet data size: 33 bytes
    [1: uint8_t format][32: uint8_t hash]

Where 'format' is the image data format, one of the following:

    0 = AVATAR_FORMAT_NONE  (no avatar set)
    1 = AVATAR_FORMAT_PNG

and 'hash' is the SHA-256 message digest of the avatar data.

This packet may be sent at any time and no previous request is required.
Clients should send this packet upon connection or when a friend
connects, in the same way Tox sends name, status and action information.





### Requesting avatar data

Transmission of avatar data is a multi-step procedure using three new packet
types.

  - Packet `PACKET_ID_AVATAR_DATA_CONTROL` have the format:

        PACKET_ID_AVATAR_DATA_CONTROL (54)
        Packet data size: 1 byte
        [1: uint8_t op]

    where 'op' is a code signaling both an operation request or a status
    return, which semantics are explained bellow. The following values are
    defined:

        0 = AVATAR_DATACONTROL_REQ
        1 = AVATAR_DATACONTROL_ERROR


  - Packet `PACKET_ID_AVATAR_DATA_START` have the following format:

        PACKET_ID_AVATAR_DATA_START (55)
        Packet data size: 37 bytes
        [1: uint8_t format][32: uint8_t hash][1: uint32_t data_length]


    where 'format' is the image format, with the same values accepted for
    the field 'format' in packet type `PACKET_ID_AVATAR_INFO`, 'hash' is
    the SHA-256 cryptographic hash of the avatar raw data and 'data_length'
    is the total number of bytes the raw avatar data.


  - Packet `PACKET_ID_AVATAR_DATA_PUSH` have no format structure, just up
    to `AVATAR_DATA_MAX_CHUNK_SIZE` bytes of raw avatar image data; this
    value is defined according to the maximum amount of data a Tox crypted
    packet can hold.



The following procedure assumes that a client "A" is requesting avatar data
from a client "B":

  - "A" must initialize its control structures and mark its data transfer
    as not yet started. Then it requests avatar data from "B" by sending a
    packet `PACKET_ID_AVATAR_DATA_CONTROL` with 'op' set to
    `AVATAR_DATACONTROL_REQ`.

  - If "B" accepts this transfer, it answers by sending an
    `PACKET_ID_AVATAR_DATA_START` with the fields 'format', 'hash' and
    'data_length' set to the respective values from the current avatar.
    If "B" have no avatar set, 'format' must be `AVATAR_FORMAT_NONE`, 'hash'
    must be zeroed and 'data_length' must be zero.

    If "B" does not accept sending the avatar, it may send a packet
    `PACKET_ID_AVATAR_DATA_CONTROL` with the field 'op' set to
    `AVATAR_DATACONTROL_ERROR` or simply ignore this request. "A" must cope
    with this.

    If "B" have an avatar, it sends a variable number of
    `PACKET_ID_AVATAR_DATA_PUSH` packets with the avatar data in a single
    shot.

  - Upon receiving a `PACKET_ID_AVATAR_DATA_START`, "A" checks if it
    has sent a data request to "B". If not, just ignores the packet.

    If "A" really requested avatar data and the format is `AVATAR_FORMAT_NONE`,
    it triggers the avatar data callback, and clears all the temporary data,
    finishing the process. For other formats, "A" just waits for packets
    of type `PACKET_ID_AVATAR_DATA_PUSH`.

  - Upon receiving a `PACKET_ID_AVATAR_DATA_PUSH`, "A" checks if it really
    sent an avatar data request and if the `PACKET_ID_AVATAR_DATA_START` was
    already received. If this conditions are valid, it checks if the total
    length of the data already stored in the receiving buffer plus the data
    present in the push packet is still less or equal than
    `TOX_AVATAR_MAX_DATA_LENGTH`. If invalid, it replies with a
    `PACKET_ID_AVATAR_DATA_CONTROL` with the field 'op' set to
    `AVATAR_DATACONTROL_ERROR`.

    If valid, "A" updates the 'bytes_received' counter and concatenates the
    newly arrived data to the buffer.

    The "A" checks if all the data was already received by comparing the
    counter 'bytes_received' with the field 'total_length'. If they are
    equal, "A" takes a SHA-256 hash of the data and compares it with the
    hash stored in the field 'hash' received from the first
    `PACKET_ID_AVATAR_DATA_START`.

    If the hashes match, the avatar data was correctly received and "A"
    triggers the avatar data callback, and clears all the temporary data,
    finishing the process.

    If not all data was received, "A" simply waits for more data.

    Client "A" is always responsible for controlling the transfer and
    validating the data received. "B" don't need to keep any state for the
    protocol, have full control over the data sent and should implement
    some transfer limit for the data it sends.

  - Any peer receiving a `PACKET_ID_AVATAR_DATA_CONTROL` with the field 'op'
    set to `AVATAR_DATACONTROL_ERROR` clears any existing control state and
    finishes sending or receiving data.





## Security considerations

The major security implication of background data transfers of large objects,
like avatars, is the possibility of exhausting the network resources from a
client. This problem is exacerbated when there is the possibility of an
amplification attack as happens, for example, when sending a very small
avatar request message will force the user to reply with a larger avatar
data message.

The present proposal mitigates this situation by:

  - Only transferring data between previously authenticated friends;

  - Enforcing strict limits on the avatar data size;

  - Providing an alternate, smaller, message to cooperative users refresh
    avatar information when nothing has changed (`PACKET_ID_AVATAR_INFO`);

  - Having per-friend data transfer limit. As the current protocol still
    allows an user to request avatar data again and again, the implementation
    limits the amount of data a particular user can request for some time. The
    exact values are defined in constants `AVATAR_DATA_TRANSFER_LIMIT` and
    `AVATAR_DATA_TRANSFER_TIMEOUT` in file `Messenger.c`.

  - Making the requester responsible for storing partial data and state
    information;

Another problem present in the avatars is the possibility of a friend send
a maliciously crafted image intended to exploit vulnerabilities in image
decoders. Without an intermediate server to recompress and validate and
convert the images to neutral formats, the client applications must handle
this situation by themselves using stable and secure image libraries and
imposing limits on the maximum amount of system resources the decoding
process can take. Images coming from Tox friends must be treated in the same
way as images coming from random Internet sources.
