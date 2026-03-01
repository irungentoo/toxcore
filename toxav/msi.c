/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "msi.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#define MSI_MAXMSG_SIZE 256

/**
 * Protocol:
 *
 * `|id [1 byte]| |size [1 byte]| |data [$size bytes]| |...{repeat}| |0 {end byte}|`
 */

typedef enum MSIHeaderID {
    ID_REQUEST = 1,
    ID_ERROR,
    ID_CAPABILITIES,
} MSIHeaderID;

typedef enum MSIRequest {
    REQU_INIT,
    REQU_PUSH,
    REQU_POP,
} MSIRequest;

typedef struct MSIHeaderRequest {
    MSIRequest value;
    bool exists;
} MSIHeaderRequest;

typedef struct MSIHeaderError {
    MSIError value;
    bool exists;
} MSIHeaderError;

typedef struct MSIHeaderCapabilities {
    uint8_t value;
    bool exists;
} MSIHeaderCapabilities;

typedef struct MSIMessage {
    MSIHeaderRequest      request;
    MSIHeaderError        error;
    MSIHeaderCapabilities capabilities;
} MSIMessage;

static void msg_init(MSIMessage *_Nonnull dest, MSIRequest request);
static void kill_call(const Logger *_Nonnull log, MSICall *_Nonnull call);
static int msg_parse_in(const Logger *_Nonnull log, MSIMessage *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);
static uint8_t *_Nonnull msg_parse_header_out(MSIHeaderID id, uint8_t *_Nonnull dest, const uint8_t *_Nonnull value, uint8_t value_len,
        uint16_t *_Nonnull length);
static int send_message(const Logger *_Nonnull log, MSISession *_Nonnull session, uint32_t friend_number, const MSIMessage *_Nonnull msg);
static int send_error(const Logger *_Nonnull log, MSISession *_Nonnull session, uint32_t friend_number, MSIError error);
static MSICall *_Nullable get_call(MSISession *_Nonnull session, uint32_t friend_number);
static MSICall *_Nullable new_call(MSISession *_Nonnull session, uint32_t friend_number);
static bool invoke_callback(const Logger *_Nonnull log, MSICall *_Nonnull call, MSICallbackID cb);
static void handle_init(const Logger *_Nonnull log, MSICall *_Nonnull call, const MSIMessage *_Nonnull msg);
static void handle_push(const Logger *_Nonnull log, MSICall *_Nonnull call, const MSIMessage *_Nonnull msg);
static void handle_pop(const Logger *_Nonnull log, MSICall *_Nonnull call, const MSIMessage *_Nonnull msg);

/*
 * Public functions
 */

MSISession *msi_new(const Logger *log, msi_send_packet_cb *send_packet, void *send_packet_user_data,
                    const MSICallbacks *callbacks, void *user_data)
{
    MSISession *retu = (MSISession *)calloc(1, sizeof(MSISession));

    if (retu == nullptr) {
        LOGGER_ERROR(log, "Allocation failed! Program might misbehave!");
        return nullptr;
    }

    if (create_recursive_mutex(retu->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to init mutex! Program might misbehave");
        free(retu);
        return nullptr;
    }

    retu->send_packet = send_packet;
    retu->send_packet_user_data = send_packet_user_data;
    retu->user_data = user_data;

    retu->invite_callback = callbacks->invite;
    retu->start_callback = callbacks->start;
    retu->end_callback = callbacks->end;
    retu->error_callback = callbacks->error;
    retu->peertimeout_callback = callbacks->peertimeout;
    retu->capabilities_callback = callbacks->capabilities;

    LOGGER_DEBUG(log, "New msi session: %p ", (void *)retu);
    return retu;
}

int msi_kill(const Logger *log, MSISession *session)
{
    if (session == nullptr) {
        LOGGER_ERROR(log, "Tried to terminate non-existing session");
        return -1;
    }

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (session->calls != nullptr) {
        MSIMessage msg;
        msg_init(&msg, REQU_POP);

        MSICall *it = get_call(session, session->calls_head);

        while (it != nullptr) {
            send_message(log, session, it->friend_number, &msg);
            MSICall *temp_it = it;
            it = it->next;
            kill_call(log, temp_it); /* This will eventually free session->calls */
        }
    }

    pthread_mutex_unlock(session->mutex);
    pthread_mutex_destroy(session->mutex);

    LOGGER_DEBUG(log, "Terminated session: %p", (void *)session);
    free(session);
    return 0;
}

void msi_call_timeout(MSISession *session, const Logger *log, uint32_t friend_number)
{
    if (session == nullptr) {
        return;
    }

    pthread_mutex_lock(session->mutex);
    MSICall *call = get_call(session, friend_number);

    if (call == nullptr) {
        pthread_mutex_unlock(session->mutex);
        return;
    }

    invoke_callback(log, call, MSI_ON_PEERTIMEOUT); /* Failure is ignored */
    kill_call(log, call);
    pthread_mutex_unlock(session->mutex);
}

int msi_invite(const Logger *log, MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities)
{
    LOGGER_DEBUG(log, "msi_invite:session:%p", (void *)session);

    if (session == nullptr) {
        return -1;
    }

    LOGGER_DEBUG(log, "Session: %p Inviting friend: %u", (void *)session, friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (get_call(session, friend_number) != nullptr) {
        LOGGER_ERROR(log, "Already in a call");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    MSICall *temp = new_call(session, friend_number);

    if (temp == nullptr) {
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    temp->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_INIT);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(log, session, temp->friend_number, &msg);

    temp->state = MSI_CALL_REQUESTING;

    *call = temp;

    LOGGER_DEBUG(log, "Invite sent");
    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_hangup(const Logger *log, MSICall *call)
{
    if (call == nullptr || call->session == nullptr) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_DEBUG(log, "Session: %p Hanging up call with friend: %u", (void *)call->session,
                 call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state == MSI_CALL_INACTIVE) {
        LOGGER_ERROR(log, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    MSIMessage msg;
    msg_init(&msg, REQU_POP);

    send_message(log, session, call->friend_number, &msg);

    kill_call(log, call);
    pthread_mutex_unlock(session->mutex);
    return 0;
}

int msi_answer(const Logger *log, MSICall *call, uint8_t capabilities)
{
    if (call == nullptr || call->session == nullptr) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_DEBUG(log, "Session: %p Answering call from: %u", (void *)call->session,
                 call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state != MSI_CALL_REQUESTED) {
        /* Though sending in invalid state will not cause anything weird
         * Its better to not do it like a maniac */
        LOGGER_ERROR(log, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_PUSH);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(log, session, call->friend_number, &msg);

    call->state = MSI_CALL_ACTIVE;
    pthread_mutex_unlock(session->mutex);

    return 0;
}

int msi_change_capabilities(const Logger *log, MSICall *call, uint8_t capabilities)
{
    if (call == nullptr || call->session == nullptr) {
        return -1;
    }

    MSISession *session = call->session;

    LOGGER_DEBUG(log, "Session: %p Trying to change capabilities to friend %u", (void *)call->session,
                 call->friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR(log, "Failed to acquire lock on msi mutex");
        return -1;
    }

    if (call->state != MSI_CALL_ACTIVE) {
        LOGGER_ERROR(log, "Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, REQU_PUSH);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message(log, session, call->friend_number, &msg);

    pthread_mutex_unlock(session->mutex);
    return 0;
}

/**
 * Private functions
 */
static void msg_init(MSIMessage *dest, MSIRequest request)
{
    memset(dest, 0, sizeof(*dest));
    dest->request.exists = true;
    dest->request.value = request;
}

static bool check_size(const Logger *_Nonnull log, const uint8_t *_Nonnull bytes, int *_Nonnull constraint, uint8_t size)
{
    *constraint -= 2 + size;

    if (*constraint < 1) {
        LOGGER_ERROR(log, "Read over length!");
        return false;
    }

    if (bytes[1] != size) {
        LOGGER_ERROR(log, "Invalid data size!");
        return false;
    }

    return true;
}

/** Assumes size == 1 */
static bool check_enum_high(const Logger *_Nonnull log, const uint8_t *_Nonnull bytes, uint8_t enum_high)
{
    if (bytes[2] > enum_high) {
        LOGGER_ERROR(log, "Failed enum high limit!");
        return false;
    }

    return true;
}

static const uint8_t *_Nullable msg_parse_one(const Logger *_Nonnull log, MSIMessage *_Nonnull dest, const uint8_t *_Nonnull it, int *_Nonnull size_constraint)
{
    switch (*it) {
        case ID_REQUEST: {
            if (!check_size(log, it, size_constraint, 1) ||
                    !check_enum_high(log, it, REQU_POP)) {
                return nullptr;
            }

            dest->request.value = (MSIRequest)it[2];
            dest->request.exists = true;
            return it + 3;
        }

        case ID_ERROR: {
            if (!check_size(log, it, size_constraint, 1) ||
                    !check_enum_high(log, it, MSI_E_UNDISCLOSED)) {
                return nullptr;
            }

            dest->error.value = (MSIError)it[2];
            dest->error.exists = true;
            return it + 3;
        }

        case ID_CAPABILITIES: {
            if (!check_size(log, it, size_constraint, 1)) {
                return nullptr;
            }

            dest->capabilities.value = it[2];
            dest->capabilities.exists = true;
            return it + 3;
        }

        default: {
            LOGGER_ERROR(log, "Invalid id byte: %d", *it);
            return nullptr;
        }
    }
}

static int msg_parse_in(const Logger *log, MSIMessage *dest, const uint8_t *data, uint16_t length)
{
    /* Parse raw data received from socket into MSIMessage struct */
    assert(dest != nullptr);

    if (length == 0 || data[length - 1] != 0) { /* End byte must have value 0 */
        LOGGER_ERROR(log, "Invalid end byte");
        return -1;
    }

    memset(dest, 0, sizeof(*dest));

    const uint8_t *it = data;
    int size_constraint = length;

    while (*it != 0) {/* until end byte is hit */
        it = msg_parse_one(log, dest, it, &size_constraint);

        if (it == nullptr) {
            return -1;
        }
    }

    if (!dest->request.exists) {
        LOGGER_ERROR(log, "Invalid request field!");
        return -1;
    }

    return 0;
}

static uint8_t *msg_parse_header_out(MSIHeaderID id, uint8_t *dest, const uint8_t *value, uint8_t value_len,
                                     uint16_t *length)
{
    /* Parse a single header for sending */
    assert(dest != nullptr);
    assert(value != nullptr);
    assert(value_len != 0);

    *dest = id;
    ++dest;
    *dest = value_len;
    ++dest;

    memcpy(dest, value, value_len);

    *length += 2 + value_len;

    return dest + value_len; /* Set to next position ready to be written */
}

static int send_message(const Logger *log, MSISession *session, uint32_t friend_number, const MSIMessage *msg)
{
    /* Parse and send message */
    uint8_t parsed[MSI_MAXMSG_SIZE];

    uint8_t *it = parsed;
    uint16_t size = 0;

    if (msg->request.exists) {
        const uint8_t cast = msg->request.value;
        it = msg_parse_header_out(ID_REQUEST, it, &cast,
                                  sizeof(cast), &size);
    } else {
        LOGGER_DEBUG(log, "Must have request field");
        return -1;
    }

    if (msg->error.exists) {
        const uint8_t cast = msg->error.value;
        it = msg_parse_header_out(ID_ERROR, it, &cast,
                                  sizeof(cast), &size);
    }

    if (msg->capabilities.exists) {
        it = msg_parse_header_out(ID_CAPABILITIES, it, &msg->capabilities.value,
                                  sizeof(msg->capabilities.value), &size);
    }

    if (it == parsed) {
        LOGGER_WARNING(log, "Parsing message failed; empty message");
        return -1;
    }

    *it = 0;
    ++size;

    if (session->send_packet != nullptr && session->send_packet(session->send_packet_user_data, friend_number, parsed, size) == 0) {
        LOGGER_DEBUG(log, "Sent message");
        return 0;
    }

    return -1;
}

static int send_error(const Logger *log, MSISession *session, uint32_t friend_number, MSIError error)
{
    /* Send error message */
    LOGGER_DEBUG(log, "Sending error: %u to friend: %u", error, friend_number);

    MSIMessage msg;
    msg_init(&msg, REQU_POP);

    msg.error.exists = true;
    msg.error.value = error;

    send_message(log, session, friend_number, &msg);
    return 0;
}

static int invoke_callback_inner(const Logger *_Nonnull log, MSICall *_Nonnull call, MSICallbackID id)
{
    MSISession *session = call->session;
    LOGGER_DEBUG(log, "invoking callback function: %u", id);

    switch (id) {
        case MSI_ON_INVITE:
            return session->invite_callback(session->user_data, call);

        case MSI_ON_START:
            return session->start_callback(session->user_data, call);

        case MSI_ON_END:
            return session->end_callback(session->user_data, call);

        case MSI_ON_ERROR:
            return session->error_callback(session->user_data, call);

        case MSI_ON_PEERTIMEOUT:
            return session->peertimeout_callback(session->user_data, call);

        case MSI_ON_CAPABILITIES:
            return session->capabilities_callback(session->user_data, call);
    }

    LOGGER_FATAL(log, "invalid callback id: %u", id);
    return -1;
}

static bool invoke_callback(const Logger *log, MSICall *call, MSICallbackID cb)
{
    assert(call != nullptr);

    if (invoke_callback_inner(log, call, cb) != 0) {
        LOGGER_WARNING(log,
                       "Callback state handling failed, sending error");

        /* If no callback present or error happened while handling,
         * an error message will be sent to friend
         */
        if (call->error == MSI_E_NONE) {
            call->error = MSI_E_HANDLE;
        }

        return false;
    }

    return true;
}

static MSICall *get_call(MSISession *session, uint32_t friend_number)
{
    assert(session != nullptr);

    if (session->calls == nullptr || session->calls_tail < friend_number) {
        return nullptr;
    }

    return session->calls[friend_number];
}

static MSICall *new_call(MSISession *session, uint32_t friend_number)
{
    assert(session != nullptr);

    MSICall *rc = (MSICall *)calloc(1, sizeof(MSICall));

    if (rc == nullptr) {
        return nullptr;
    }

    rc->session = session;
    rc->friend_number = friend_number;

    if (session->calls == nullptr) { /* Creating */
        session->calls = (MSICall **)calloc(friend_number + 1, sizeof(MSICall *));

        if (session->calls == nullptr) {
            free(rc);
            return nullptr;
        }

        session->calls_tail = friend_number;
        session->calls_head = friend_number;
    } else if (session->calls_tail < friend_number) { /* Appending */
        MSICall **tmp = (MSICall **)realloc(session->calls, (friend_number + 1) * sizeof(MSICall *));

        if (tmp == nullptr) {
            free(rc);
            return nullptr;
        }

        session->calls = tmp;

        /* Set fields in between to null */
        for (uint32_t i = session->calls_tail + 1; i < friend_number; ++i) {
            session->calls[i] = nullptr;
        }

        rc->prev = session->calls[session->calls_tail];
        session->calls[session->calls_tail]->next = rc;

        session->calls_tail = friend_number;
    } else if (session->calls_head > friend_number) { /* Inserting at front */
        rc->next = session->calls[session->calls_head];
        session->calls[session->calls_head]->prev = rc;
        session->calls_head = friend_number;
    } else { /* Inserting in a hole */
        uint32_t i = friend_number - 1;

        while (session->calls[i] == nullptr) {
            --i;
        }

        rc->prev = session->calls[i];
        rc->next = session->calls[i]->next;
        rc->prev->next = rc;

        if (rc->next != nullptr) {
            rc->next->prev = rc;
        }
    }

    session->calls[friend_number] = rc;
    return rc;
}

static void kill_call(const Logger *log, MSICall *call)
{
    /* Assume that session mutex is locked */
    if (call == nullptr) {
        return;
    }

    MSISession *session = call->session;

    LOGGER_DEBUG(log, "Killing call: %p", (void *)call);

    MSICall *prev = call->prev;
    MSICall *next = call->next;

    if (prev != nullptr) {
        prev->next = next;
    } else if (next != nullptr) {
        session->calls_head = next->friend_number;
    } else {
        goto CLEAR_CONTAINER;
    }

    if (next != nullptr) {
        next->prev = prev;
    } else if (prev != nullptr) {
        session->calls_tail = prev->friend_number;
    } else {
        goto CLEAR_CONTAINER;
    }

    session->calls[call->friend_number] = nullptr;
    free(call);
    return;

CLEAR_CONTAINER:
    session->calls_head = 0;
    session->calls_tail = 0;
    free(session->calls);
    free(call);
    session->calls = nullptr;
}


static bool try_handle_init(const Logger *_Nonnull log, MSICall *_Nonnull call, const MSIMessage *_Nonnull msg)
{
    if (!msg->capabilities.exists) {
        LOGGER_WARNING(log, "Session: %p Invalid capabilities on 'init'", (void *)call->session);
        call->error = MSI_E_INVALID_MESSAGE;
        return false;
    }

    switch (call->state) {
        case MSI_CALL_INACTIVE: {
            /* Call requested */
            call->peer_capabilities = msg->capabilities.value;
            call->state = MSI_CALL_REQUESTED;

            if (!invoke_callback(log, call, MSI_ON_INVITE)) {
                return false;
            }

            break;
        }

        case MSI_CALL_ACTIVE: {
            /* If peer sent init while the call is already
             * active it's probable that he is trying to
             * re-call us while the call is not terminated
             * on our side. We can assume that in this case
             * we can automatically answer the re-call.
             */

            LOGGER_INFO(log, "Friend is recalling us");

            if (call->peer_capabilities != msg->capabilities.value) {
                LOGGER_INFO(log, "Friend is changing capabilities to: %u", msg->capabilities.value);

                call->peer_capabilities = msg->capabilities.value;

                if (!invoke_callback(log, call, MSI_ON_CAPABILITIES)) {
                    return false;
                }
            }

            MSIMessage out_msg;
            msg_init(&out_msg, REQU_PUSH);

            out_msg.capabilities.exists = true;
            out_msg.capabilities.value = call->self_capabilities;

            send_message(log, call->session, call->friend_number, &out_msg);

            /* If peer changed capabilities during re-call they will
             * be handled accordingly during the next step
             */
            break;
        }

        case MSI_CALL_REQUESTED: // fall-through
        case MSI_CALL_REQUESTING: {
            LOGGER_WARNING(log, "Session: %p Invalid state on 'init'", (void *)call->session);
            call->error = MSI_E_INVALID_STATE;
            return false;
        }
    }

    return true;
}

static void handle_init(const Logger *log, MSICall *call, const MSIMessage *msg)
{
    assert(call != nullptr);
    LOGGER_DEBUG(log,
                 "Session: %p Handling 'init' friend: %u", (void *)call->session, call->friend_number);

    if (!try_handle_init(log, call, msg)) {
        send_error(log, call->session, call->friend_number, call->error);
        kill_call(log, call);
    }
}

static void handle_push(const Logger *log, MSICall *call, const MSIMessage *msg)
{
    assert(call != nullptr);

    LOGGER_DEBUG(log, "Session: %p Handling 'push' friend: %u", (void *)call->session,
                 call->friend_number);

    if (!msg->capabilities.exists) {
        LOGGER_WARNING(log, "Session: %p Invalid capabilities on 'push'", (void *)call->session);
        call->error = MSI_E_INVALID_MESSAGE;
        goto FAILURE;
    }

    switch (call->state) {
        case MSI_CALL_ACTIVE: {
            if (call->peer_capabilities != msg->capabilities.value) {
                LOGGER_INFO(log, "Friend is changing capabilities to: %u", msg->capabilities.value);

                call->peer_capabilities = msg->capabilities.value;

                if (!invoke_callback(log, call, MSI_ON_CAPABILITIES)) {
                    goto FAILURE;
                }
            }

            break;
        }

        case MSI_CALL_REQUESTING: {
            LOGGER_INFO(log, "Friend answered our call");

            /* Call started */
            call->peer_capabilities = msg->capabilities.value;
            call->state = MSI_CALL_ACTIVE;

            if (!invoke_callback(log, call, MSI_ON_START)) {
                goto FAILURE;
            }

            break;
        }

        case MSI_CALL_INACTIVE: // fall-through
        case MSI_CALL_REQUESTED: {
            LOGGER_WARNING(log, "Ignoring invalid push");
            break;
        }
    }

    return;

FAILURE:
    send_error(log, call->session, call->friend_number, call->error);
    kill_call(log, call);
}

static void handle_pop(const Logger *log, MSICall *call, const MSIMessage *msg)
{
    assert(call != nullptr);

    LOGGER_DEBUG(log, "Session: %p Handling 'pop', friend id: %u", (void *)call->session,
                 call->friend_number);

    /* callback errors are ignored */

    if (msg->error.exists) {
        LOGGER_WARNING(log, "Friend detected an error: %u", msg->error.value);
        call->error = msg->error.value;
        invoke_callback(log, call, MSI_ON_ERROR);
    } else {
        switch (call->state) {
            case MSI_CALL_INACTIVE: {
                LOGGER_FATAL(log, "Handling what should be impossible case");
                break;
            }

            case MSI_CALL_ACTIVE: {
                /* Hangup */
                LOGGER_INFO(log, "Friend hung up on us");
                invoke_callback(log, call, MSI_ON_END);
                break;
            }

            case MSI_CALL_REQUESTING: {
                /* Reject */
                LOGGER_INFO(log, "Friend rejected our call");
                invoke_callback(log, call, MSI_ON_END);
                break;
            }

            case MSI_CALL_REQUESTED: {
                /* Cancel */
                LOGGER_INFO(log, "Friend canceled call invite");
                invoke_callback(log, call, MSI_ON_END);
                break;
            }
        }
    }

    kill_call(log, call);
}

void msi_handle_packet(MSISession *session, const Logger *log, uint32_t friend_number, const uint8_t *data,
                       size_t length)
{
    if (session == nullptr) {
        return;
    }

    if (length < 1) {
        LOGGER_ERROR(log, "MSI packet is empty");
        return;
    }

    LOGGER_DEBUG(log, "Got msi message");

    MSIMessage msg;

    if (msg_parse_in(log, &msg, data, length) == -1) {
        LOGGER_WARNING(log, "Error parsing message");
        send_error(log, session, friend_number, MSI_E_INVALID_MESSAGE);
        return;
    }

    LOGGER_DEBUG(log, "Successfully parsed message");

    pthread_mutex_lock(session->mutex);
    MSICall *call = get_call(session, friend_number);

    if (call == nullptr) {
        if (msg.request.value != REQU_INIT) {
            send_error(log, session, friend_number, MSI_E_STRAY_MESSAGE);
            pthread_mutex_unlock(session->mutex);
            return;
        }

        call = new_call(session, friend_number);

        if (call == nullptr) {
            send_error(log, session, friend_number, MSI_E_SYSTEM);
            pthread_mutex_unlock(session->mutex);
            return;
        }
    }

    switch (msg.request.value) {
        case REQU_INIT: {
            handle_init(log, call, &msg);
            break;
        }

        case REQU_PUSH: {
            handle_push(log, call, &msg);
            break;
        }

        case REQU_POP: {
            handle_pop(log, call, &msg); /* always kills the call */
            break;
        }
    }

    pthread_mutex_unlock(session->mutex);
}
