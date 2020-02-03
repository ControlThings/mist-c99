#ifndef RB_H
#define RB_H

#define RINGBUFFER_STATE_OK      (0)
#define RINGBUFFER_STATE_WAIT    (1)
#define RINGBUFFER_STATE_END     (2)
#define RINGBUFFER_STATE_ERROR   (3)

typedef struct {
    /** Ring buffer read cursor */
    int read;
    /** Ring buffer write cursor */
    int write;
    /** Length of data in ring buffer */
    int data_len;
    /** Ring buffer memory size */
    int max_len;
    /** Ring buffer state, for communication, i.e. source can indicate end of stream or an error */
    uint8_t state;
    /** Pointer to ring buffer data memory */
    uint8_t* data;
} ring_buffer_t;



/**
 * Initialize ring buffer from buffer structure, data pointer and length
 * 
 * @param buf
 * @param data
 * @param len
 */
void ring_buffer_init(ring_buffer_t* buf, uint8_t* data, int len);

uint8_t ring_buffer_is_full(ring_buffer_t*  buf);

uint8_t ring_buffer_is_empty(ring_buffer_t*  buf);

/**
 * Return the amount of data in buffer 
 * 
 * @param buf
 * @return 
 */
int ring_buffer_length(ring_buffer_t*  buf);

/**
 * Return the amount of free space in buffer
 * 
 * @param buf
 * @return 
 */
int ring_buffer_space(ring_buffer_t*  buf);

int ring_buffer_write(ring_buffer_t*  buf, const uint8_t* data, int len);

int ring_buffer_read(ring_buffer_t*  buf, uint8_t* data, int len);

/**
 * Skip len bytes from buffer
 * 
 * Works like read, but does not copy the data anywhere.
 * 
 * @param buf
 * @param len
 * @return 
 */
int ring_buffer_skip(ring_buffer_t*  buf, int len);

int ring_buffer_peek(ring_buffer_t*  buf, uint8_t* data, int len);

/* This function returns the smaller of two values */
int min(int a, int b);

#endif //RB_H
