#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

/* Ring buffer */
typedef struct RingBuffer RingBuffer;
bool rb_full(const RingBuffer *b);
bool rb_empty(const RingBuffer *b);
void *rb_write(RingBuffer *b, void *p);
bool rb_read(RingBuffer *b, void **p);
RingBuffer *rb_new(int size);
void rb_kill(RingBuffer *b);
uint16_t rb_size(const RingBuffer *b);
uint16_t rb_data(const RingBuffer *b, void **dest);

#endif /* RING_BUFFER_H */
