/**  msi.c
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "msi.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#define MSI_MAXMSG_SIZE 256

/**
 * Protocol:
 *
 * |id [1 byte]| |size [1 byte]| |data [$size bytes]| |...{repeat}| |0 {end byte}|
 */

typedef enum {
    IDRequest = 1,
    IDError,
    IDCapabilities,

} MSIHeaderID;


typedef enum {
    requ_init,
    requ_push,
    requ_pop,
} MSIRequest;


#define GENERIC_HEADER(header, val_type) \
typedef struct { \
    val_type value; \
    bool exists; \
} MSIHeader##header


GENERIC_HEADER (Request, MSIRequest);
GENERIC_HEADER (Error, MSIError);
GENERIC_HEADER (Capabilities, uint8_t);


typedef struct {
    MSIHeaderRequest      request;
    MSIHeaderError        error;
    MSIHeaderCapabilities capabilities;
} MSIMessage;


void msg_init (MSIMessage *dest, MSIRequest request);
int msg_parse_in (MSIMessage *dest, const uint8_t *data, uint16_t length);
uint8_t *msg_parse_header_out (MSIHeaderID id, uint8_t *dest, const void *value, uint8_t value_len, uint16_t *length);
static int send_message (Messenger *m, uint32_t friend_number, const MSIMessage *msg);
int send_error (Messenger *m, uint32_t friend_number, MSIError error);
static int invoke_callback(MSICall *call, MSICallbackID cb);
static MSICall *get_call (MSISession *session, uint32_t friend_number);
MSICall *new_call (MSISession *session, uint32_t friend_number);
void kill_call (MSICall *call);
void on_peer_status(Messenger *m, uint32_t friend_number, uint8_t status, void *data);
void handle_init (MSICall *call, const MSIMessage *msg);
void handle_push (MSICall *call, const MSIMessage *msg);
void handle_pop (MSICall *call, const MSIMessage *msg);
void handle_msi_packet (Messenger *m, uint32_t friend_number, const uint8_t *data, uint16_t length, void *object);


/**
 * Public functions
 */
void msi_register_callback (MSISession *session, msi_action_cb *callback, MSICallbackID id)
{
    if (!session)
        return;

    pthread_mutex_lock(session->mutex);
    session->callbacks[id] = callback;
    pthread_mutex_unlock(session->mutex);
}
MSISession *msi_new (Messenger *m)
{
    if (m == NULL) {
        LOGGER_ERROR("Could not init session on empty messenger!");
        return NULL;
    }

    MSISession *retu = calloc (sizeof (MSISession), 1);

    if (retu == NULL) {
        LOGGER_ERROR("Allocation failed! Program might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(retu->mutex) != 0) {
        LOGGER_ERROR("Failed to init mutex! Program might misbehave");
        free(retu);
        return NULL;
    }

    retu->messenger = m;

    m_callback_msi_packet(m, handle_msi_packet, retu);

    /* This is called when remote terminates session */
    m_callback_connectionstatus_internal_av(m, on_peer_status, retu);

    LOGGER_DEBUG("New msi session: %p ", retu);
    return retu;
}
int msi_kill (MSISession *session)
{
    if (session == NULL) {
        LOGGER_ERROR("Tried to terminate non-existing session");
        return -1;
    }

    m_callback_msi_packet((struct Messenger *) session->messenger, NULL, NULL);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR ("Failed to aquire lock on msi mutex");
        return -1;
    }

    if (session->calls) {
        MSIMessage msg;
        msg_init(&msg, requ_pop);

        MSICall *it = get_call(session, session->calls_head);

        while (it) {
            send_message(session->messenger, it->friend_number, &msg);
            MSICall *temp_it = it;
            it = it->next;
            kill_call(temp_it); /* This will eventually free session->calls */
        }
    }

    pthread_mutex_unlock(session->mutex);
    pthread_mutex_destroy(session->mutex);

    LOGGER_DEBUG("Terminated session: %p", session);
    free (session);
    return 0;
}
int msi_invite (MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities)
{
    if (!session)
        return -1;

    LOGGER_DEBUG("Session: %p Inviting friend: %u", session, friend_number);

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR ("Failed to aquire lock on msi mutex");
        return -1;
    }

    if (get_call(session, friend_number) != NULL) {
        LOGGER_ERROR("Already in a call");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    (*call) = new_call (session, friend_number);

    if (*call == NULL) {
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    (*call)->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, requ_init);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message ((*call)->session->messenger, (*call)->friend_number, &msg);

    (*call)->state = msi_CallRequesting;

    LOGGER_DEBUG("Invite sent");
    pthread_mutex_unlock(session->mutex);
    return 0;
}
int msi_hangup (MSICall *call)
{
    if (!call || !call->session)
        return -1;

    LOGGER_DEBUG("Session: %p Hanging up call with friend: %u", call->session, call->friend_number);

    MSISession *session = call->session;

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR ("Failed to aquire lock on msi mutex");
        return -1;
    }

    if (call->state == msi_CallInactive) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    MSIMessage msg;
    msg_init(&msg, requ_pop);

    send_message (session->messenger, call->friend_number, &msg);

    kill_call(call);
    pthread_mutex_unlock(session->mutex);
    return 0;
}
int msi_answer (MSICall *call, uint8_t capabilities)
{
    if (!call || !call->session)
        return -1;

    LOGGER_DEBUG("Session: %p Answering call from: %u", call->session, call->friend_number);

    MSISession *session = call->session;

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR ("Failed to aquire lock on msi mutex");
        return -1;
    }

    if (call->state != msi_CallRequested) {
        /* Though sending in invalid state will not cause anything wierd
         * Its better to not do it like a maniac */
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, requ_push);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message (session->messenger, call->friend_number, &msg);

    call->state = msi_CallActive;
    pthread_mutex_unlock(session->mutex);

    return 0;
}
int msi_change_capabilities(MSICall *call, uint8_t capabilities)
{
    if (!call || !call->session)
        return -1;

    LOGGER_DEBUG("Session: %p Trying to change capabilities to friend %u", call->session, call->friend_number);

    MSISession *session = call->session;

    if (pthread_mutex_trylock(session->mutex) != 0) {
        LOGGER_ERROR ("Failed to aquire lock on msi mutex");
        return -1;
    }

    if (call->state != msi_CallActive) {
        LOGGER_ERROR("Call is in invalid state!");
        pthread_mutex_unlock(session->mutex);
        return -1;
    }

    call->self_capabilities = capabilities;

    MSIMessage msg;
    msg_init(&msg, requ_push);

    msg.capabilities.exists = true;
    msg.capabilities.value = capabilities;

    send_message (call->session->messenger, call->friend_number, &msg);

    pthread_mutex_unlock(session->mutex);
    return 0;
}


/**
 * Private functions
 */
void msg_init(MSIMessage *dest, MSIRequest request)
{
    memset(dest, 0, sizeof(*dest));
    dest->request.exists = true;
    dest->request.value = request;
}
int msg_parse_in (MSIMessage *dest, const uint8_t *data, uint16_t length)
{
    /* Parse raw data received from socket into MSIMessage struct */

#define CHECK_SIZE(bytes, constraint, size) \
    if ((constraint -= (2 + size)) < 1) { LOGGER_ERROR("Read over length!"); return -1; } \
    if (bytes[1] != size) { LOGGER_ERROR("Invalid data size!"); return -1; }

#define CHECK_ENUM_HIGH(bytes, enum_high) /* Assumes size == 1 */ \
    if (bytes[2] > enum_high) { LOGGER_ERROR("Failed enum high limit!"); return -1; }

#define SET_UINT8(bytes, header) do { \
        header.value = bytes[2]; \
        header.exists = true; \
        bytes += 3; \
    } while(0)

#define SET_UINT16(bytes, header) do { \
        memcpy(&header.value, bytes + 2, 2);\
        header.exists = true; \
        bytes += 4; \
    } while(0)


    assert(dest);

    if (length == 0 || data[length - 1]) { /* End byte must have value 0 */
        LOGGER_ERROR("Invalid end byte");
        return -1;
    }

    memset(dest, 0, sizeof(*dest));

    const uint8_t *it = data;
    int size_constraint = length;

    while (*it) {/* until end byte is hit */
        switch (*it) {
            case IDRequest:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, requ_pop);
                SET_UINT8(it, dest->request);
                break;

            case IDError:
                CHECK_SIZE(it, size_constraint, 1);
                CHECK_ENUM_HIGH(it, msi_EUndisclosed);
                SET_UINT8(it, dest->error);
                break;

            case IDCapabilities:
                CHECK_SIZE(it, size_constraint, 1);
                SET_UINT8(it, dest->capabilities);
                break;

            default:
                LOGGER_ERROR("Invalid id byte");
                return -1;
                break;
        }
    }

    if (dest->request.exists == false) {
        LOGGER_ERROR("Invalid request field!");
        return -1;
    }

    return 0;

#undef CHECK_SIZE
#undef CHECK_ENUM_HIGH
#undef SET_UINT8
#undef SET_UINT16
}
uint8_t *msg_parse_header_out (MSIHeaderID id, uint8_t *dest, const void *value, uint8_t value_len, uint16_t *length)
{
    /* Parse a single header for sending */
    assert(dest);
    assert(value);
    assert(value_len);

    *dest = id;
    dest ++;
    *dest = value_len;
    dest ++;

    memcpy(dest, value, value_len);

    *length += (2 + value_len);

    return dest + value_len; /* Set to next position ready to be written */
}
int send_message (Messenger *m, uint32_t friend_number, const MSIMessage *msg)
{
    /* Parse and send message */
    assert(m);

    uint8_t parsed [MSI_MAXMSG_SIZE];

    uint8_t *it = parsed;
    uint16_t size = 0;

    if (msg->request.exists) {
        uint8_t cast = msg->request.value;
        it = msg_parse_header_out(IDRequest, it, &cast,
                                  sizeof(cast), &size);
    } else {
        LOGGER_DEBUG("Must have request field");
        return -1;
    }

    if (msg->error.exists) {
        uint8_t cast = msg->error.value;
        it = msg_parse_header_out(IDError, it, &cast,
                                  sizeof(cast), &size);
    }

    if (msg->capabilities.exists) {
        it = msg_parse_header_out(IDCapabilities, it, &msg->capabilities.value,
                                  sizeof(msg->capabilities.value), &size);
    }

    if (it == parsed) {
        LOGGER_WARNING("Parsing message failed; empty message");
        return -1;
    }

    *it = 0;
    size ++;

    if (m_msi_packet(m, friend_number, parsed, size)) {
        LOGGER_DEBUG("Sent message");
        return 0;
    }

    return -1;
}
int send_error (Messenger *m, uint32_t friend_number, MSIError error)
{
    /* Send error message */
    assert(m);

    LOGGER_DEBUG("Sending error: %d to friend: %d", error, friend_number);

    MSIMessage msg;
    msg_init(&msg, requ_pop);

    msg.error.exists = true;
    msg.error.value = error;

    send_message (m, friend_number, &msg);
    return 0;
}
int invoke_callback(MSICall *call, MSICallbackID cb)
{
    assert(call);

    if (call->session->callbacks[cb]) {
        LOGGER_DEBUG("Invoking callback function: %d", cb);

        if (call->session->callbacks[cb] (call->session->av, call) != 0) {
            LOGGER_WARNING("Callback state handling failed, sending error");
            goto FAILURE;
        }

        return 0;
    }

FAILURE:
    /* If no callback present or error happened while handling,
     * an error message will be sent to friend
     */

    if (call->error == msi_ENone)
        call->error = msi_EHandle;

    return -1;
}
static MSICall *get_call (MSISession *session, uint32_t friend_number)
{
    assert(session);

    if (session->calls == NULL || session->calls_tail < friend_number)
        return NULL;

    return session->calls[friend_number];
}
MSICall *new_call (MSISession *session, uint32_t friend_number)
{
    assert(session);

    MSICall *rc = calloc(sizeof(MSICall), 1);

    if (rc == NULL)
        return NULL;

    rc->session = session;
    rc->friend_number = friend_number;

    if (session->calls == NULL) { /* Creating */
        session->calls = calloc (sizeof(MSICall *), friend_number + 1);

        if (session->calls == NULL) {
            free(rc);
            return NULL;
        }

        session->calls_tail = session->calls_head = friend_number;

    } else if (session->calls_tail < friend_number) { /* Appending */
        void *tmp = realloc(session->calls, sizeof(MSICall *) * (friend_number + 1));

        if (tmp == NULL) {
            free(rc);
            return NULL;
        }

        session->calls = tmp;

        /* Set fields in between to null */
        uint32_t i = session->calls_tail + 1;

        for (; i < friend_number; i ++)
            session->calls[i] = NULL;

        rc->prev = session->calls[session->calls_tail];
        session->calls[session->calls_tail]->next = rc;

        session->calls_tail = friend_number;

    } else if (session->calls_head > friend_number) { /* Inserting at front */
        rc->next = session->calls[session->calls_head];
        session->calls[session->calls_head]->prev = rc;
        session->calls_head = friend_number;
    }

    session->calls[friend_number] = rc;
    return rc;
}
void kill_call (MSICall *call)
{
    /* Assume that session mutex is locked */
    if (call == NULL)
        return;

    LOGGER_DEBUG("Killing call: %p", call);

    MSISession *session = call->session;

    MSICall *prev = call->prev;
    MSICall *next = call->next;

    if (prev)
        prev->next = next;
    else if (next)
        session->calls_head = next->friend_number;
    else goto CLEAR_CONTAINER;

    if (next)
        next->prev = prev;
    else if (prev)
        session->calls_tail = prev->friend_number;
    else goto CLEAR_CONTAINER;

    session->calls[call->friend_number] = NULL;
    free(call);
    return;

CLEAR_CONTAINER:
    session->calls_head = session->calls_tail = 0;
    free(session->calls);
    free(call);
    session->calls = NULL;
}
void on_peer_status(Messenger *m, uint32_t friend_number, uint8_t status, void *data)
{
    (void)m;
    MSISession *session = data;

    switch (status) {
        case 0: { /* Friend is now offline */
            LOGGER_DEBUG("Friend %d is now offline", friend_number);

            pthread_mutex_lock(session->mutex);
            MSICall *call = get_call(session, friend_number);

            if (call == NULL) {
                pthread_mutex_unlock(session->mutex);
                return;
            }

            invoke_callback(call, msi_OnPeerTimeout); /* Failure is ignored */
            kill_call(call);
            pthread_mutex_unlock(session->mutex);
        }
        break;

        default:
            break;
    }
}
void handle_init (MSICall *call, const MSIMessage *msg)
{
    assert(call);
    LOGGER_DEBUG("Session: %p Handling 'init' friend: %d", call->session, call->friend_number);

    if (!msg->capabilities.exists) {
        LOGGER_WARNING("Session: %p Invalid capabilities on 'init'");
        call->error = msi_EInvalidMessage;
        goto FAILURE;
    }

    switch (call->state) {
        case msi_CallInactive: {
            /* Call requested */
            call->peer_capabilities = msg->capabilities.value;
            call->state = msi_CallRequested;

            if (invoke_callback(call, msi_OnInvite) == -1)
                goto FAILURE;
        }
        break;

        case msi_CallActive: {
            /* If peer sent init while the call is already
             * active it's probable that he is trying to
             * re-call us while the call is not terminated
             * on our side. We can assume that in this case
             * we can automatically answer the re-call.
             */

            LOGGER_INFO("Friend is recalling us");

            MSIMessage msg;
            msg_init(&msg, requ_push);

            msg.capabilities.exists = true;
            msg.capabilities.value = call->self_capabilities;

            send_message (call->session->messenger, call->friend_number, &msg);

            /* If peer changed capabilities during re-call they will
             * be handled accordingly during the next step
             */
        }
        break;

        default: {
            LOGGER_WARNING("Session: %p Invalid state on 'init'");
            call->error = msi_EInvalidState;
            goto FAILURE;
        }
        break;
    }

    return;
FAILURE:
    send_error(call->session->messenger, call->friend_number, call->error);
    kill_call(call);
}
void handle_push (MSICall *call, const MSIMessage *msg)
{
    assert(call);

    LOGGER_DEBUG("Session: %p Handling 'push' friend: %d", call->session, call->friend_number);

    if (!msg->capabilities.exists) {
        LOGGER_WARNING("Session: %p Invalid capabilities on 'push'");
        call->error = msi_EInvalidMessage;
        goto FAILURE;
    }

    switch (call->state) {
        case msi_CallActive: {
            /* Only act if capabilities changed */
            if (call->peer_capabilities != msg->capabilities.value) {
                LOGGER_INFO("Friend is changing capabilities to: %u", msg->capabilities.value);

                call->peer_capabilities = msg->capabilities.value;

                if (invoke_callback(call, msi_OnCapabilities) == -1)
                    goto FAILURE;
            }
        }
        break;

        case msi_CallRequesting: {
            LOGGER_INFO("Friend answered our call");

            /* Call started */
            call->peer_capabilities = msg->capabilities.value;
            call->state = msi_CallActive;

            if (invoke_callback(call, msi_OnStart) == -1)
                goto FAILURE;

        }
        break;

        /* Pushes during initialization state are ignored */
        case msi_CallInactive:
        case msi_CallRequested: {
            LOGGER_WARNING("Ignoring invalid push");
        }
        break;
    }

    return;

FAILURE:
    send_error(call->session->messenger, call->friend_number, call->error);
    kill_call(call);
}
void handle_pop (MSICall *call, const MSIMessage *msg)
{
    assert(call);

    LOGGER_DEBUG("Session: %p Handling 'pop', friend id: %d", call->session, call->friend_number);

    /* callback errors are ignored */

    if (msg->error.exists) {
        LOGGER_WARNING("Friend detected an error: %d", msg->error.value);
        call->error = msg->error.value;
        invoke_callback(call, msi_OnError);

    } else switch (call->state) {
            case msi_CallInactive: {
                LOGGER_ERROR("Handling what should be impossible case");
                abort();
            }
            break;

            case msi_CallActive: {
                /* Hangup */
                LOGGER_INFO("Friend hung up on us");
                invoke_callback(call, msi_OnEnd);
            }
            break;

            case msi_CallRequesting: {
                /* Reject */
                LOGGER_INFO("Friend rejected our call");
                invoke_callback(call, msi_OnEnd);
            }
            break;

            case msi_CallRequested: {
                /* Cancel */
                LOGGER_INFO("Friend canceled call invite");
                invoke_callback(call, msi_OnEnd);
            }
            break;
        }

    kill_call (call);
}
void handle_msi_packet (Messenger *m, uint32_t friend_number, const uint8_t *data, uint16_t length, void *object)
{
    LOGGER_DEBUG("Got msi message");

    MSISession *session = object;
    MSIMessage msg;

    if (msg_parse_in (&msg, data, length) == -1) {
        LOGGER_WARNING("Error parsing message");
        send_error(m, friend_number, msi_EInvalidMessage);
        return;
    } else {
        LOGGER_DEBUG("Successfully parsed message");
    }

    pthread_mutex_lock(session->mutex);
    MSICall *call = get_call(session, friend_number);

    if (call == NULL) {
        if (msg.request.value != requ_init) {
            send_error(m, friend_number, msi_EStrayMessage);
            pthread_mutex_unlock(session->mutex);
            return;
        }

        call = new_call(session, friend_number);

        if (call == NULL) {
            send_error(m, friend_number, msi_ESystem);
            pthread_mutex_unlock(session->mutex);
            return;
        }
    }

    switch (msg.request.value) {
        case requ_init:
            handle_init(call, &msg);
            break;

        case requ_push:
            handle_push(call, &msg);
            break;

        case requ_pop:
            handle_pop(call, &msg); /* always kills the call */
            break;
    }

    pthread_mutex_unlock(session->mutex);
}
