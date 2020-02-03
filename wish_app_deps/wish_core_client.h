#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_app.h"
#include "rb.h"

typedef enum core_client_state {
    CORE_CLIENT_STATE_INITIAL,
    CORE_CLIENT_STATE_DISCONNECTED,
    CORE_CLIENT_STATE_CONNECTING,
    CORE_CLIENT_STATE_CONNECTED
} core_client_state;


typedef struct wish_core_client {
    core_client_state state;
    int wait_counter;
    wish_app_t* app;
    ring_buffer_t* rb;
    uv_loop_t* loop;
    uv_connect_t* connect_req;
    uv_stream_t* tcp_stream;
    uv_tcp_t* tcp;
    uv_timer_t* timeout;
    int frame_state;
    int frame_expect;
    struct wish_core_client* next;
    struct wish_core_client* prev;

    bool cont_flag;
    size_t cont_received_so_far;
    size_t cont_total_len;
    uint8_t* cont_buffer;
} wish_core_client_t;

void wish_core_client_init(wish_app_t *app);

void wish_core_client_close(wish_app_t* app);

#ifdef __cplusplus
}
#endif
