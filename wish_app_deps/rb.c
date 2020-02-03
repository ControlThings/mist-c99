#include <stdint.h>
#include "rb.h"
#include "stdio.h"

void ring_buffer_init(ring_buffer_t* buf, uint8_t* data, int len) {
    buf->read = 0;
    buf->data_len = 0;
    buf->data = data;
    buf->max_len = len;
    buf->state = RINGBUFFER_STATE_WAIT;
}


uint8_t ring_buffer_is_full(ring_buffer_t* buf) {
    if ( buf->data_len == buf->max_len ) {
        return 1;
    } else {
        return 0;
    }
}

uint8_t ring_buffer_is_empty(ring_buffer_t* buf) {
    if ( buf->data_len == 0 ) {
        return 1;
    } else {
        return 0;
    }
}

int ring_buffer_length(ring_buffer_t* buf) {
    return buf->data_len;
}

int ring_buffer_space(ring_buffer_t* buf) {
    return buf->max_len - buf->data_len;
}

int ring_buffer_write(ring_buffer_t* buf, const uint8_t* data, int len) {
    int wrote = 0;
    int cursor = (buf->read+buf->data_len)%buf->max_len;
    while (wrote<len) {
        if ( ring_buffer_is_full(buf) ) {
            return wrote;
        } else {
            buf->data[cursor] = data[wrote];
            wrote++;
            buf->data_len++;
            cursor = (buf->read+buf->data_len)%buf->max_len;
        }
    }
    return wrote;
}

int ring_buffer_read(ring_buffer_t* buf, uint8_t* data, int len) {
    int read = 0;
    int cursor = buf->read;
    while (read<len) {
        if ( ring_buffer_is_empty(buf) ) {
            printf("==================ring_buffer_read less than len: read: %i, len: %i\n", read, len);
            return read;
        } else {
            data[read] = buf->data[cursor];
            read++;
            buf->data_len--;
            ++buf->read;
            buf->read %= buf->max_len;
            cursor = buf->read;
        }
    }
    return read;
}

int ring_buffer_skip(ring_buffer_t* buf, int len) {
    int read = 0;
    while (read<len) {
        if ( ring_buffer_is_empty(buf) ) {
            return read;
        } else {
            read++;
            buf->data_len--;
            ++buf->read;
            buf->read %= buf->max_len;
        }
    }
    return read;
}

int ring_buffer_peek(ring_buffer_t* buf, uint8_t* data, int len) {
    int read = 0;
    int cursor = buf->read;
    // Peek a maximum of data_len bytes
    if ( buf->data_len < len ) {
        len = buf->data_len;
    }
    while (read<len) {
        data[read] = buf->data[cursor];
        read++;
        cursor++;
        cursor %= buf->max_len;
    }
    return read;
}



