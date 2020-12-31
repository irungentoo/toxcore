/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * An implementation of a simple text chat only messenger on the tox network
 * core.
 */
#ifndef C_TOXCORE_TOXCORE_MESSENGER_H
#define C_TOXCORE_TOXCORE_MESSENGER_H

#include "TCP_server.h"
#include "announce.h"
#include "forwarding.h"
#include "friend_connection.h"
#include "friend_requests.h"
#include "logger.h"
#include "net_crypto.h"
#include "state.h"

#define MAX_NAME_LENGTH 128
/* TODO(irungentoo): this must depend on other variable. */
#define MAX_STATUSMESSAGE_LENGTH 1007
/* Used for TCP relays in Messenger struct (may need to be `% 2 == 0`)*/
#define NUM_SAVED_TCP_RELAYS 8
/* This cannot be bigger than 256 */
#define MAX_CONCURRENT_FILE_PIPES 256


#define FRIEND_ADDRESS_SIZE (CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

typedef enum Message_Type {
    MESSAGE_NORMAL,
    MESSAGE_ACTION,
} Message_Type;

typedef struct Messenger Messenger;

// Returns the size of the data
typedef uint32_t m_state_size_cb(const Messenger *m);

// Returns the new pointer to data
typedef uint8_t *m_state_save_cb(const Messenger *m, uint8_t *data);

// Returns if there were any erros during loading
typedef State_Load_Status m_state_load_cb(Messenger *m, const uint8_t *data, uint32_t length);

typedef struct Messenger_State_Plugin {
    State_Type type;
    m_state_size_cb *size;
    m_state_save_cb *save;
    m_state_load_cb *load;
} Messenger_State_Plugin;

typedef struct Messenger_Options {
    bool ipv6enabled;
    bool udp_disabled;
    TCP_Proxy_Info proxy_info;
    uint16_t port_range[2];
    uint16_t tcp_server_port;

    bool hole_punching_enabled;
    bool local_discovery_enabled;
    bool dht_announcements_enabled;

    logger_cb *log_callback;
    void *log_context;
    void *log_user_data;

    Messenger_State_Plugin *state_plugins;
    uint8_t state_plugins_length;
} Messenger_Options;


struct Receipts {
    uint32_t packet_num;
    uint32_t msg_id;
    struct Receipts *next;
};

/** Status definitions. */
typedef enum Friend_Status {
    NOFRIEND,
    FRIEND_ADDED,
    FRIEND_REQUESTED,
    FRIEND_CONFIRMED,
    FRIEND_ONLINE,
} Friend_Status;

/** @brief Errors for m_addfriend
 *
 * FAERR - Friend Add Error
 */
typedef enum Friend_Add_Error {
    FAERR_TOOLONG = -1,
    FAERR_NOMESSAGE = -2,
    FAERR_OWNKEY = -3,
    FAERR_ALREADYSENT = -4,
    FAERR_BADCHECKSUM = -6,
    FAERR_SETNEWNOSPAM = -7,
    FAERR_NOMEM = -8,
} Friend_Add_Error;


/** Default start timeout in seconds between friend requests. */
#define FRIENDREQUEST_TIMEOUT 5

typedef enum Connection_Status {
    CONNECTION_NONE,
    CONNECTION_TCP,
    CONNECTION_UDP,
} Connection_Status;

/**
 * Represents userstatuses someone can have.
 */
typedef enum Userstatus {
    USERSTATUS_NONE,
    USERSTATUS_AWAY,
    USERSTATUS_BUSY,
    USERSTATUS_INVALID,
} Userstatus;

#define FILE_ID_LENGTH 32

struct File_Transfers {
    uint64_t size;
    uint64_t transferred;
    uint8_t status; /* 0 == no transfer, 1 = not accepted, 3 = transferring, 4 = broken, 5 = finished */
    uint8_t paused; /* 0: not paused, 1 = paused by us, 2 = paused by other, 3 = paused by both. */
    uint32_t last_packet_number; /* number of the last packet sent. */
    uint64_t requested; /* total data requested by the request chunk callback */
    uint8_t id[FILE_ID_LENGTH];
};
typedef enum Filestatus {
    FILESTATUS_NONE,
    FILESTATUS_NOT_ACCEPTED,
    FILESTATUS_TRANSFERRING,
    // FILESTATUS_BROKEN,
    FILESTATUS_FINISHED,
} Filestatus;

typedef enum File_Pause {
    FILE_PAUSE_NOT,
    FILE_PAUSE_US,
    FILE_PAUSE_OTHER,
    FILE_PAUSE_BOTH,
} File_Pause;

typedef enum Filecontrol {
    FILECONTROL_ACCEPT,
    FILECONTROL_PAUSE,
    FILECONTROL_KILL,
    FILECONTROL_SEEK,
} Filecontrol;

typedef enum Filekind {
    FILEKIND_DATA,
    FILEKIND_AVATAR,
} Filekind;


typedef void m_self_connection_status_cb(Messenger *m, Onion_Connection_Status connection_status, void *user_data);
typedef void m_friend_status_cb(Messenger *m, uint32_t friend_number, unsigned int status, void *user_data);
typedef void m_friend_connection_status_cb(Messenger *m, uint32_t friend_number, unsigned int connection_status,
        void *user_data);
typedef void m_friend_message_cb(Messenger *m, uint32_t friend_number, unsigned int message_type,
                                 const uint8_t *message, size_t length, void *user_data);
typedef void m_file_recv_control_cb(Messenger *m, uint32_t friend_number, uint32_t file_number, unsigned int control,
                                    void *user_data);
typedef void m_friend_request_cb(Messenger *m, const uint8_t *public_key, const uint8_t *message, size_t length,
                                 void *user_data);
typedef void m_friend_name_cb(Messenger *m, uint32_t friend_number, const uint8_t *name, size_t length,
                              void *user_data);
typedef void m_friend_status_message_cb(Messenger *m, uint32_t friend_number, const uint8_t *message, size_t length,
                                        void *user_data);
typedef void m_friend_typing_cb(Messenger *m, uint32_t friend_number, bool is_typing, void *user_data);
typedef void m_friend_read_receipt_cb(Messenger *m, uint32_t friend_number, uint32_t message_id, void *user_data);
typedef void m_file_recv_cb(Messenger *m, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                            uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data);
typedef void m_file_chunk_request_cb(Messenger *m, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                     size_t length, void *user_data);
typedef void m_file_recv_chunk_cb(Messenger *m, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                  const uint8_t *data, size_t length, void *user_data);
typedef void m_friend_lossy_packet_cb(Messenger *m, uint32_t friend_number, uint8_t packet_id, const uint8_t *data,
                                      size_t length, void *user_data);
typedef void m_friend_lossless_packet_cb(Messenger *m, uint32_t friend_number, uint8_t packet_id, const uint8_t *data,
        size_t length, void *user_data);
typedef void m_friend_connectionstatuschange_internal_cb(Messenger *m, uint32_t friend_number,
        uint8_t connection_status, void *user_data);
typedef void m_conference_invite_cb(Messenger *m, uint32_t friend_number, const uint8_t *cookie, uint16_t length,
                                    void *user_data);
typedef void m_msi_packet_cb(Messenger *m, uint32_t friend_number, const uint8_t *data, uint16_t length,
                             void *user_data);
typedef int m_lossy_rtp_packet_cb(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t len, void *object);

typedef struct RTP_Packet_Handler {
    m_lossy_rtp_packet_cb *function;
    void *object;
} RTP_Packet_Handler;

typedef struct Friend {
    uint8_t real_pk[CRYPTO_PUBLIC_KEY_SIZE];
    int friendcon_id;

    uint64_t friendrequest_lastsent; // Time at which the last friend request was sent.
    uint32_t friendrequest_timeout; // The timeout between successful friendrequest sending attempts.
    uint8_t status; // 0 if no friend, 1 if added, 2 if friend request sent, 3 if confirmed friend, 4 if online.
    uint8_t info[MAX_FRIEND_REQUEST_DATA_SIZE]; // the data that is sent during the friend requests we do.
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;
    bool name_sent; // false if we didn't send our name to this friend, true if we have.
    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;
    bool statusmessage_sent;
    Userstatus userstatus;
    bool userstatus_sent;
    bool user_istyping;
    bool user_istyping_sent;
    bool is_typing;
    uint16_t info_size; // Length of the info.
    uint32_t message_id; // a semi-unique id used in read receipts.
    uint32_t friendrequest_nospam; // The nospam number used in the friend request.
    uint64_t last_seen_time;
    Connection_Status last_connection_udp_tcp;
    struct File_Transfers file_sending[MAX_CONCURRENT_FILE_PIPES];
    uint32_t num_sending_files;
    struct File_Transfers file_receiving[MAX_CONCURRENT_FILE_PIPES];

    RTP_Packet_Handler lossy_rtp_packethandlers[PACKET_ID_RANGE_LOSSY_AV_SIZE];

    struct Receipts *receipts_start;
    struct Receipts *receipts_end;
} Friend;

struct Messenger {
    Logger *log;
    Mono_Time *mono_time;
    const Random *rng;
    const Network *ns;

    Networking_Core *net;
    Net_Crypto *net_crypto;
    DHT *dht;

    Forwarding *forwarding;
    Announcements *announce;

    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;

    Friend_Connections *fr_c;

    TCP_Server *tcp_server;
    Friend_Requests *fr;
    uint8_t name[MAX_NAME_LENGTH];
    uint16_t name_length;

    uint8_t statusmessage[MAX_STATUSMESSAGE_LENGTH];
    uint16_t statusmessage_length;

    Userstatus userstatus;

    Friend *friendlist;
    uint32_t numfriends;

    uint64_t lastdump;
    uint8_t is_receiving_file;

    bool has_added_relays; // If the first connection has occurred in do_messenger

    uint16_t num_loaded_relays;
    Node_format loaded_relays[NUM_SAVED_TCP_RELAYS]; // Relays loaded from config

    m_friend_request_cb *friend_request;
    m_friend_message_cb *friend_message;
    m_friend_name_cb *friend_namechange;
    m_friend_status_message_cb *friend_statusmessagechange;
    m_friend_status_cb *friend_userstatuschange;
    m_friend_typing_cb *friend_typingchange;
    m_friend_read_receipt_cb *read_receipt;
    m_friend_connection_status_cb *friend_connectionstatuschange;
    m_friend_connectionstatuschange_internal_cb *friend_connectionstatuschange_internal;
    void *friend_connectionstatuschange_internal_userdata;

    struct Group_Chats *conferences_object; /* Set by new_groupchats()*/
    m_conference_invite_cb *conference_invite;

    m_file_recv_cb *file_sendrequest;
    m_file_recv_control_cb *file_filecontrol;
    m_file_recv_chunk_cb *file_filedata;
    m_file_chunk_request_cb *file_reqchunk;

    m_msi_packet_cb *msi_packet;
    void *msi_packet_userdata;

    m_friend_lossy_packet_cb *lossy_packethandler;
    m_friend_lossless_packet_cb *lossless_packethandler;

    m_self_connection_status_cb *core_connection_change;
    Onion_Connection_Status last_connection_status;

    Messenger_Options options;
};

/**
 * Format: `[real_pk (32 bytes)][nospam number (4 bytes)][checksum (2 bytes)]`
 *
 * @param[out] address FRIEND_ADDRESS_SIZE byte address to give to others.
 */
non_null()
void getaddress(const Messenger *m, uint8_t *address);

/**
 * Add a friend.
 *
 * Set the data that will be sent along with friend request.
 *
 * @param address is the address of the friend (returned by getaddress of the friend
 *   you wish to add) it must be FRIEND_ADDRESS_SIZE bytes.
 *   TODO(irungentoo): add checksum.
 * @param data is the data.
 * @param length is the length.
 *
 * @return the friend number if success.
 * @retval FA_TOOLONG if message length is too long.
 * @retval FAERR_NOMESSAGE if no message (message length must be >= 1 byte).
 * @retval FAERR_OWNKEY if user's own key.
 * @retval FAERR_ALREADYSENT if friend request already sent or already a friend.
 * @retval FAERR_BADCHECKSUM if bad checksum in address.
 * @retval FAERR_SETNEWNOSPAM if the friend was already there but the nospam was different.
 *   (the nospam for that friend was set to the new one).
 * @retval FAERR_NOMEM if increasing the friend list size fails.
 */
non_null()
int32_t m_addfriend(Messenger *m, const uint8_t *address, const uint8_t *data, uint16_t length);


/** @brief Add a friend without sending a friendrequest.
 * @return the friend number if success.
 * @retval -3 if user's own key.
 * @retval -4 if friend request already sent or already a friend.
 * @retval -6 if bad checksum in address.
 * @retval -8 if increasing the friend list size fails.
 */
non_null()
int32_t m_addfriend_norequest(Messenger *m, const uint8_t *real_pk);

/** @return the friend number associated to that public key.
 * @retval -1 if no such friend.
 */
non_null()
int32_t getfriend_id(const Messenger *m, const uint8_t *real_pk);

/** @brief Copies the public key associated to that friend id into real_pk buffer.
 *
 * Make sure that real_pk is of size CRYPTO_PUBLIC_KEY_SIZE.
 *
 * @retval 0 if success.
 * @retval -1 if failure.
 */
non_null()
int get_real_pk(const Messenger *m, int32_t friendnumber, uint8_t *real_pk);

/** @return friend connection id on success.
 * @retval -1 if failure.
 */
non_null()
int getfriendcon_id(const Messenger *m, int32_t friendnumber);

/** @brief Remove a friend.
 *
 * @retval 0 if success.
 * @retval -1 if failure.
 */
non_null()
int m_delfriend(Messenger *m, int32_t friendnumber);

/** @brief Checks friend's connection status.
 *
 * @retval CONNECTION_UDP (2) if friend is directly connected to us (Online UDP).
 * @retval CONNECTION_TCP (1) if friend is connected to us (Online TCP).
 * @retval CONNECTION_NONE (0) if friend is not connected to us (Offline).
 * @retval -1 on failure.
 */
non_null()
int m_get_friend_connectionstatus(const Messenger *m, int32_t friendnumber);

/**
 * Checks if there exists a friend with given friendnumber.
 *
 * @param friendnumber The index in the friend list.
 *
 * @retval true if friend exists.
 * @retval false if friend doesn't exist.
 */
non_null()
bool m_friend_exists(const Messenger *m, int32_t friendnumber);

/** @brief Send a message of type to an online friend.
 *
 * @retval -1 if friend not valid.
 * @retval -2 if too large.
 * @retval -3 if friend not online.
 * @retval -4 if send failed (because queue is full).
 * @retval -5 if bad type.
 * @retval 0 if success.
 *
 * The value in message_id will be passed to your read_receipt callback when the other receives the message.
 */
non_null(1, 4) nullable(6)
int m_send_message_generic(Messenger *m, int32_t friendnumber, uint8_t type, const uint8_t *message, uint32_t length,
                           uint32_t *message_id);


/** @brief Set the name and name_length of a friend.
 *
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 * @retval 0 if success.
 * @retval -1 if failure.
 */
non_null()
int setfriendname(Messenger *m, int32_t friendnumber, const uint8_t *name, uint16_t length);

/** @brief Set our nickname.
 *
 * name must be a string of maximum MAX_NAME_LENGTH length.
 * length must be at least 1 byte.
 * length is the length of name with the NULL terminator.
 *
 * @retval 0 if success.
 * @retval -1 if failure.
 */
non_null()
int setname(Messenger *m, const uint8_t *name, uint16_t length);

/**
 * @brief Get your nickname.
 *
 * m - The messenger context to use.
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH bytes.
 *
 * @return length of the name.
 * @retval 0 on error.
 */
non_null()
uint16_t getself_name(const Messenger *m, uint8_t *name);

/** @brief Get name of friendnumber and put it in name.
 *
 * name needs to be a valid memory location with a size of at least MAX_NAME_LENGTH (128) bytes.
 *
 * @return length of name if success.
 * @retval -1 if failure.
 */
non_null()
int getname(const Messenger *m, int32_t friendnumber, uint8_t *name);

/** @return the length of name, including null on success.
 * @retval -1 on failure.
 */
non_null() int m_get_name_size(const Messenger *m, int32_t friendnumber);
non_null() int m_get_self_name_size(const Messenger *m);

/** @brief Set our user status.
 * You are responsible for freeing status after.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
non_null() int m_set_statusmessage(Messenger *m, const uint8_t *status, uint16_t length);
non_null() int m_set_userstatus(Messenger *m, uint8_t status);

/**
 * Guaranteed to be at most MAX_STATUSMESSAGE_LENGTH.
 *
 * @return the length of friendnumber's status message, including null on success.
 * @retval -1 on failure.
 */
non_null() int m_get_statusmessage_size(const Messenger *m, int32_t friendnumber);
non_null() int m_get_self_statusmessage_size(const Messenger *m);

/** @brief Copy friendnumber's status message into buf, truncating if size is over maxlen.
 *
 * Get the size you need to allocate from m_get_statusmessage_size.
 * The self variant will copy our own status message.
 *
 * @return the length of the copied data on success
 * @retval -1 on failure.
 */
non_null() int m_copy_statusmessage(const Messenger *m, int32_t friendnumber, uint8_t *buf, uint32_t maxlen);
non_null() int m_copy_self_statusmessage(const Messenger *m, uint8_t *buf);

/** @brief return one of Userstatus values.
 *
 * Values unknown to your application should be represented as USERSTATUS_NONE.
 * As above, the self variant will return our own Userstatus.
 * If friendnumber is invalid, this shall return USERSTATUS_INVALID.
 */
non_null() uint8_t m_get_userstatus(const Messenger *m, int32_t friendnumber);
non_null() uint8_t m_get_self_userstatus(const Messenger *m);


/** @brief returns timestamp of last time friendnumber was seen online or 0 if never seen.
 * if friendnumber is invalid this function will return UINT64_MAX.
 */
non_null() uint64_t m_get_last_online(const Messenger *m, int32_t friendnumber);

/** @brief Set our typing status for a friend.
 * You are responsible for turning it on or off.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
non_null()
int m_set_usertyping(Messenger *m, int32_t friendnumber, bool is_typing);

/** @brief Get the typing status of a friend.
 *
 * @retval -1 if friend number is invalid.
 * @retval 0 if friend is not typing.
 * @retval 1 if friend is typing.
 */
non_null()
int m_get_istyping(const Messenger *m, int32_t friendnumber);

/** Set the function that will be executed when a friend request is received. */
non_null(1) nullable(2)
void m_callback_friendrequest(Messenger *m, m_friend_request_cb *function);

/** Set the function that will be executed when a message from a friend is received. */
non_null() void m_callback_friendmessage(Messenger *m, m_friend_message_cb *function);

/** @brief Set the callback for name changes.
 * You are not responsible for freeing newname.
 */
non_null() void m_callback_namechange(Messenger *m, m_friend_name_cb *function);

/** @brief Set the callback for status message changes.
 *
 * You are not responsible for freeing newstatus
 */
non_null() void m_callback_statusmessage(Messenger *m, m_friend_status_message_cb *function);

/** @brief Set the callback for status type changes. */
non_null() void m_callback_userstatus(Messenger *m, m_friend_status_cb *function);

/** @brief Set the callback for typing changes. */
non_null() void m_callback_typingchange(Messenger *m, m_friend_typing_cb *function);

/** @brief Set the callback for read receipts.
 *
 * If you are keeping a record of returns from m_sendmessage,
 * receipt might be one of those values, meaning the message
 * has been received on the other side.
 * Since core doesn't track ids for you, receipt may not correspond to any message.
 * In that case, you should discard it.
 */
non_null() void m_callback_read_receipt(Messenger *m, m_friend_read_receipt_cb *function);

/** @brief Set the callback for connection status changes.
 *
 * Status:
 * - 0: friend went offline after being previously online.
 * - 1: friend went online.
 *
 * Note that this callback is not called when adding friends, thus the
 * "after being previously online" part.
 * It's assumed that when adding friends, their connection status is offline.
 */
non_null() void m_callback_connectionstatus(Messenger *m, m_friend_connection_status_cb *function);

/** Same as previous but for internal A/V core usage only */
non_null() void m_callback_connectionstatus_internal_av(
    Messenger *m, m_friend_connectionstatuschange_internal_cb *function, void *userdata);


/** @brief Set the callback for typing changes. */
non_null() void m_callback_core_connection(Messenger *m, m_self_connection_status_cb *function);

/*** CONFERENCES */

/** @brief Set the callback for conference invites. */
non_null(1) nullable(2)
void m_callback_conference_invite(Messenger *m, m_conference_invite_cb *function);

/** @brief Send a conference invite packet.
 *
 * return true on success
 * return false on failure
 */
non_null()
bool send_conference_invite_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length);

/*** FILE SENDING */


/** @brief Set the callback for file send requests. */
non_null() void callback_file_sendrequest(Messenger *m, m_file_recv_cb *function);


/** @brief Set the callback for file control requests. */
non_null() void callback_file_control(Messenger *m, m_file_recv_control_cb *function);

/** @brief Set the callback for file data. */
non_null() void callback_file_data(Messenger *m, m_file_recv_chunk_cb *function);

/** @brief Set the callback for file request chunk. */
non_null() void callback_file_reqchunk(Messenger *m, m_file_chunk_request_cb *function);


/** @brief Copy the file transfer file id to file_id
 *
 * @retval 0 on success.
 * @retval -1 if friend not valid.
 * @retval -2 if filenumber not valid
 */
non_null()
int file_get_id(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint8_t *file_id);

/** @brief Send a file send request.
 *
 * Maximum filename length is 255 bytes.
 *
 * @return file number on success
 * @retval -1 if friend not found.
 * @retval -2 if filename length invalid.
 * @retval -3 if no more file sending slots left.
 * @retval -4 if could not send packet (friend offline).
 */
non_null()
long int new_filesender(const Messenger *m, int32_t friendnumber, uint32_t file_type, uint64_t filesize,
                        const uint8_t *file_id, const uint8_t *filename, uint16_t filename_length);

/** @brief Send a file control request.
 *
 * @retval 0 on success
 * @retval -1 if friend not valid.
 * @retval -2 if friend not online.
 * @retval -3 if file number invalid.
 * @retval -4 if file control is bad.
 * @retval -5 if file already paused.
 * @retval -6 if resume file failed because it was only paused by the other.
 * @retval -7 if resume file failed because it wasn't paused.
 * @retval -8 if packet failed to send.
 */
non_null()
int file_control(const Messenger *m, int32_t friendnumber, uint32_t filenumber, unsigned int control);

/** @brief Send a seek file control request.
 *
 * @retval 0 on success
 * @retval -1 if friend not valid.
 * @retval -2 if friend not online.
 * @retval -3 if file number invalid.
 * @retval -4 if not receiving file.
 * @retval -5 if file status wrong.
 * @retval -6 if position bad.
 * @retval -8 if packet failed to send.
 */
non_null()
int file_seek(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint64_t position);

/** @brief Send file data.
 *
 * @retval 0 on success
 * @retval -1 if friend not valid.
 * @retval -2 if friend not online.
 * @retval -3 if filenumber invalid.
 * @retval -4 if file transfer not transferring.
 * @retval -5 if bad data size.
 * @retval -6 if packet queue full.
 * @retval -7 if wrong position.
 */
non_null(1) nullable(5)
int send_file_data(const Messenger *m, int32_t friendnumber, uint32_t filenumber, uint64_t position, const uint8_t *data, uint16_t length);

/*** A/V related */

/** @brief Set the callback for msi packets. */
non_null(1) nullable(2, 3)
void m_callback_msi_packet(Messenger *m, m_msi_packet_cb *function, void *userdata);

/** @brief Send an msi packet.
 *
 * @retval true on success
 * @retval false on failure
 */
non_null()
bool m_msi_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint16_t length);

/** @brief Set handlers for lossy rtp packets.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null(1) nullable(4, 5)
int m_callback_rtp_packet(Messenger *m, int32_t friendnumber, uint8_t byte,
                          m_lossy_rtp_packet_cb *function, void *object);

/*** CUSTOM PACKETS */

/** @brief Set handlers for custom lossy packets. */
non_null() void custom_lossy_packet_registerhandler(Messenger *m, m_friend_lossy_packet_cb *lossy_packethandler);

/** @brief High level function to send custom lossy packets.
 *
 * TODO(oxij): this name is confusing, because this function sends both av and custom lossy packets.
 * Meanwhile, m_handle_lossy_packet routes custom packets to custom_lossy_packet_registerhandler
 * as you would expect from its name.
 *
 * I.e. custom_lossy_packet_registerhandler's "custom lossy packet" and this "custom lossy packet"
 * are not the same set of packets.
 *
 * @retval -1 if friend invalid.
 * @retval -2 if length wrong.
 * @retval -3 if first byte invalid.
 * @retval -4 if friend offline.
 * @retval -5 if packet failed to send because of other error.
 * @retval 0 on success.
 */
non_null()
int m_send_custom_lossy_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);


/** @brief Set handlers for custom lossless packets. */
non_null()
void custom_lossless_packet_registerhandler(Messenger *m, m_friend_lossless_packet_cb *lossless_packethandler);

/** @brief High level function to send custom lossless packets.
 *
 * @retval -1 if friend invalid.
 * @retval -2 if length wrong.
 * @retval -3 if first byte invalid.
 * @retval -4 if friend offline.
 * @retval -5 if packet failed to send because of other error.
 * @retval 0 on success.
 */
non_null()
int send_custom_lossless_packet(const Messenger *m, int32_t friendnumber, const uint8_t *data, uint32_t length);

/*** Messenger constructor/destructor/operations. */

typedef enum Messenger_Error {
    MESSENGER_ERROR_NONE,
    MESSENGER_ERROR_PORT,
    MESSENGER_ERROR_TCP_SERVER,
    MESSENGER_ERROR_OTHER,
} Messenger_Error;

/** @brief Run this at startup.
 *
 * @return allocated instance of Messenger on success.
 * @retval 0 if there are problems.
 *
 * if error is not NULL it will be set to one of the values in the enum above.
 */
non_null()
Messenger *new_messenger(Mono_Time *mono_time, const Random *rng, const Network *ns, Messenger_Options *options, Messenger_Error *error);

/** @brief Run this before closing shop.
 *
 * Free all datastructures.
 */
nullable(1)
void kill_messenger(Messenger *m);

/** @brief The main loop that needs to be run at least 20 times per second. */
non_null(1) nullable(2)
void do_messenger(Messenger *m, void *userdata);

/**
 * @brief Return the time in milliseconds before `do_messenger()` should be called again
 *   for optimal performance.
 *
 * @return time (in ms) before the next `do_messenger()` needs to be run on success.
 */
non_null()
uint32_t messenger_run_interval(const Messenger *m);

/* SAVING AND LOADING FUNCTIONS: */

/** @brief Registers a state plugin for saving, loading, and getting the size of a section of the save.
 *
 * @retval true on success
 * @retval false on error
 */
non_null()
bool m_register_state_plugin(Messenger *m, State_Type type,
                             m_state_size_cb *size_callback,
                             m_state_load_cb *load_callback,
                             m_state_save_cb *save_callback);

/** return size of the messenger data (for saving). */
non_null()
uint32_t messenger_size(const Messenger *m);

/** Save the messenger in data (must be allocated memory of size at least `Messenger_size()`) */
non_null()
uint8_t *messenger_save(const Messenger *m, uint8_t *data);

/** @brief Load a state section.
 *
 * @param data Data to load.
 * @param length Length of data.
 * @param type Type of section (`STATE_TYPE_*`).
 * @param status Result of loading section is stored here if the section is handled.
 * @return true iff section handled.
 */
non_null()
bool messenger_load_state_section(Messenger *m, const uint8_t *data, uint32_t length, uint16_t type,
                                  State_Load_Status *status);

/** @brief Return the number of friends in the instance m.
 *
 * You should use this to determine how much memory to allocate
 * for copy_friendlist.
 */
non_null()
uint32_t count_friendlist(const Messenger *m);

/** @brief Copy a list of valid friend IDs into the array out_list.
 * If out_list is NULL, returns 0.
 * Otherwise, returns the number of elements copied.
 * If the array was too small, the contents
 * of out_list will be truncated to list_size.
 */
non_null()
uint32_t copy_friendlist(const Messenger *m, uint32_t *out_list, uint32_t list_size);

non_null()
bool m_is_receiving_file(Messenger *m);

#endif
