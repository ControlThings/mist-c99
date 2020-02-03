#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "wish_protocol.h"

/* This defines the size of the buffer were the RPC reply will be
 * built */
#define RPC_REPLY_BUF_LEN 1460

#define APP_NAME_MAX_LEN 16

typedef struct app_s {
    char name[APP_NAME_MAX_LEN];
    wish_app_t* app;
    wish_protocol_handler_t protocol;
    void (*online)(struct app_s* app, wish_protocol_peer_t* peer);
    void (*offline)(struct app_s* app, wish_protocol_peer_t* peer);
    void (*frame)(struct app_s* app, const uint8_t* payload, size_t payload_len, wish_protocol_peer_t* peer);
    struct app_s* next;
} app_t;

app_t* app_get_new_context(void);

app_t* app_init(void);

rpc_id app_respond(app_t* app, wish_protocol_peer_t* peer, uint8_t* response, size_t response_len, rpc_client_callback cb);

rpc_id app_request(app_t* app, wish_protocol_peer_t* peer, uint8_t* request, size_t request_len, rpc_client_callback cb);

app_t* app_lookup_by_wsid(uint8_t* wsid);

#ifdef __cplusplus
}
#endif
