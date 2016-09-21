#include "ring_buffer.h"

#include <stdlib.h>

struct RingBuffer {
    uint16_t size; /* Max size */
    uint16_t start;
    uint16_t end;
    void   **data;
};

bool rb_full(const RingBuffer *b)
{
    return (b->end + 1) % b->size == b->start;
}
bool rb_empty(const RingBuffer *b)
{
    return b->end == b->start;
}
void *rb_write(RingBuffer *b, void *p)
{
    void *rc = NULL;

    if ((b->end + 1) % b->size == b->start) { /* full */
        rc = b->data[b->start];
    }

    b->data[b->end] = p;
    b->end = (b->end + 1) % b->size;

    if (b->end == b->start) {
        b->start = (b->start + 1) % b->size;
    }

    return rc;
}
bool rb_read(RingBuffer *b, void **p)
{
    if (b->end == b->start) { /* Empty */
        *p = NULL;
        return false;
    }

    *p = b->data[b->start];
    b->start = (b->start + 1) % b->size;
    return true;
}
RingBuffer *rb_new(int size)
{
    RingBuffer *buf = (RingBuffer *)calloc(sizeof(RingBuffer), 1);

    if (!buf) {
        return NULL;
    }

    buf->size = size + 1; /* include empty elem */

    if (!(buf->data = (void **)calloc(buf->size, sizeof(void *)))) {
        free(buf);
        return NULL;
    }

    return buf;
}
void rb_kill(RingBuffer *b)
{
    if (b) {
        free(b->data);
        free(b);
    }
}
uint16_t rb_size(const RingBuffer *b)
{
    if (rb_empty(b)) {
        return 0;
    }

    return
        b->end > b->start ?
        b->end - b->start :
        (b->size - b->start) + b->end;
}
uint16_t rb_data(const RingBuffer *b, void **dest)
{
    uint16_t i = 0;

    for (; i < rb_size(b); i++) {
        dest[i] = b->data[(b->start + i) % b->size];
    }

    return i;
}
