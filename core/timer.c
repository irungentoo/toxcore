#include "timer.h"
#include "network.h"
#include <stdint.h>

/* 
A nested linked list increases efficiency of insertions.
Depending on the number of timers we have, we might need to have nested linked lists
in order to improve insertion efficiency.
The code below is preperation for that end, should it be necessary.

typedef struct {
    struct timer_package* _next;
    union {
        timer_packet* _inner;
        timer* queue;
    };
    uint64_t pkgtime;
} timer_package;

timer_package* timer_package_pool;

static timer_package* new_package()
{
    timer_package* ret;
    if (timer_package_pool) {
        ret = timer_package_pool;
        timer_package_pool = timer_package_pool->_next;
    } else {
        ret = calloc(1, sizeof(struct timer_package));
    }
    return ret;
}

static void delete_package(timer_package* p)
{
    p->_next = timer_package_pool;
    timer_package_pool = p;
}
*/

enum timer_state {
    STATE_INACTIVE = 0,
    STATE_ACTIVE,
    STATE_CALLBACK
};

struct timer
{
    enum timer_state state;
    timer* _prev;
    timer* _next;
    timer_callback cb;
    void* userdata;
    uint64_t deadline;
};

static timer* timer_main_queue;
static timer* timer_us_queue; /* hi-speed queue */

inline static void timer_dequeue(timer* t, timer** queue)
{
    if (t->state == STATE_INACTIVE) return; /* not in a queue */
    
    if (t->_prev) {
        t->_prev->_next = t->_next;
    } else {
        *queue = t->_next;
    }
    if (t->_next) t->_next->_prev = t->_prev;
    t->state = STATE_INACTIVE;
}

static void timer_enqueue(timer* t, timer** queue, timer* prev)
{
    t->state = STATE_ACTIVE;
    while (true) {
        if (!*queue) {
            t->_next = 0;
            t->_prev = prev;
            *queue = t;
            return;
        }

        if ((*queue)->deadline > t->deadline) {
            (*queue)->_prev = t;
            t->_next = *queue;
            t->_prev = prev;
            *queue = t;
            return;
        }

        prev = *queue;
        queue = &((*queue)->_next);
    }
}

/*** interface ***/

void timer_init()
{
    /* Nothing needs to be done... yet. */
}

/* Do not depend on fields being zeroed */
static timer* timer_pool; /* timer_pool is SINGLY LINKED!! */

timer* timer_new(void)
{
    timer* ret;
    if (timer_pool) {
        ret = timer_pool;
        timer_pool = timer_pool->_next;
    } else {
        ret = calloc(1, sizeof(struct timer));
    }
    ret->state = STATE_INACTIVE;
    return ret;
}

void timer_delete(timer* t)
{
    timer_dequeue(t, &timer_main_queue);
    t->_next = timer_pool;
    t->state = STATE_INACTIVE;
    timer_pool = t;
}

void timer_setup(timer* t, timer_callback cb, void* userarg)
{
    t->cb = cb;
    t->userdata = userarg;
}

void* timer_get_userdata(timer* t)
{
    return t->userdata;
}

static void timer_delay_us(timer* t, int us)
{
    t->deadline += us;
    timer** queue = t->_prev ? &(t->_prev->_next) : &timer_main_queue;
    timer_dequeue(t, &timer_main_queue);
    timer_enqueue(t, queue, t->_prev);
}

/* Starts the timer so that it's called in sec seconds in the future. 
 * A non-positive value of sec results in the callback being called immediately.
 * This function may be called again after a timer has been started to adjust 
 * the expiry time. */
void timer_start(timer* t, int sec)
{
    uint64_t newdeadline = current_time() + sec * US_PER_SECOND;
    if (timer_is_active(t)){
        if (t->deadline < newdeadline) {
            timer_delay_us(t, newdeadline - t->deadline);
            return;
        }
        timer_dequeue(t, &timer_main_queue);
    }
    t->deadline = newdeadline;
    timer_enqueue(t, &timer_main_queue, 0);
}

/* Stops the timer. Returns -1 if the timer was not active. */
int timer_stop(timer* t)
{
    int ret = timer_is_active(t) ? -1 : 0;
    timer_dequeue(t, &timer_main_queue);
    return ret;
}

/* Adds additionalsec seconds to the timer. 
 * Returns -1 and does nothing if the timer was not active. */
int timer_delay(timer* t, int additonalsec)
{
    if (!timer_is_active(t)) return -1;
    timer_delay_us(t, additonalsec * US_PER_SECOND);
    return 0;
}

static uint64_t timer_diff(timer* t, uint64_t time)
{
    if (t->deadline <= time) return 0;
    return time - t->deadline;
}

/* Returns the time remaining on a timer in seconds.
 * Returns -1 if the timer is not active.
 * Returns 0 if the timer has expired and will be called upon the next call to timer_poll. */
int timer_time_remaining(timer* t)
{
    if (!timer_is_active(t)) return -1;
    return timer_diff(t, current_time()) / US_PER_SECOND;
}

bool timer_is_active(timer* t)
{
    return t->state != STATE_INACTIVE;
}

/* Single-use timer.
 * Creates a new timer, preforms setup and starts it. */
void timer_single(timer_callback cb, void* userarg, int sec)
{
    timer* t = timer_new();
    timer_setup(t, cb, userarg);
    timer_start(t, sec);
}

/* Single-use microsecond timer. */
void timer_us(timer_callback cb, void* userarg, int us)
{
    timer* t = timer_new();
    timer_setup(t, cb, userarg);
    t->deadline = current_time() + us;
    t->state = STATE_ACTIVE;
    timer_enqueue(t, &timer_us_queue, 0);
}

uint64_t prevtime = 0;
void timer_poll(void)
{
    uint64_t time = current_time();

    /* Handle millisecond timers */
    while (timer_us_queue) {
        if (timer_diff(timer_us_queue, time) != 0) break;
        timer* t = timer_us_queue;
        timer_dequeue(t, &timer_us_queue);
        t->cb(0, t->userdata);
        timer_delete(t);
    }

    if (time - prevtime > US_PER_SECOND || prevtime == 0 || prevtime > time) { 
        /* time moving backwards is just a sanity check */
        prevtime = time;
        
        while (timer_main_queue) {
            if (timer_diff(timer_main_queue, time) != 0) break;
            timer* t = timer_main_queue;
            t->state = STATE_CALLBACK;
            int rv = t->cb(t, t->userdata);
            if (rv != 0) {
                timer_dequeue(t, &timer_main_queue);
                timer_delete(t);
                continue;
            }
            if (t->state != STATE_ACTIVE) {
                timer_dequeue(t, &timer_main_queue);
            }
        }
    }
}

/*** Internal Testing ***/

/* I do not want to expose internals to the public, 
 * which is why internals testing is done this way. */
void timer_internal_tests(bool (*assert)(bool, char*))
{
    
}

void timer_debug_print()
{
    timer* t = timer_main_queue;
    printf("Queue:\n");
    while (t) {
        printf("%lli (%lli) : %s\n", t->deadline, t->deadline/US_PER_SECOND, (char*)t->userdata);
        t = t->_next;
    }
}
