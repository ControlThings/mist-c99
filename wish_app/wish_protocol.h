#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "wish_rpc.h"
#include "bson.h"

#define WISH_PROTOCOL_NAME_MAX_LEN 10

#ifndef WISH_UID_LEN
#define WISH_UID_LEN 32
#else
#if WISH_UID_LEN != 32
#error A previoud WISH_UID_LEN declaration is inconsistent!
#endif
#endif 

typedef struct {
    uint8_t luid[WISH_UID_LEN];
    uint8_t ruid[WISH_UID_LEN];
    uint8_t rhid[WISH_UID_LEN];
    uint8_t rsid[WISH_UID_LEN];
    char protocol[WISH_UID_LEN];
    bool online;
} wish_protocol_peer_t;

typedef struct {
    /* A facility for sending RPC messages, and define callbacks which
     * will be executed when the call is acked */
    rpc_client rpc_client;
    
    /* wish_rpc_server_t *rpc_server,
     * This will include a facility for dynamically define callbacks for
     * messages with different 'op's */
    //enum wish_protocol protocol;
    char protocol_name[WISH_PROTOCOL_NAME_MAX_LEN];
    /* Callback to be invoked when frame is received.
     * The argument data is the frame's payload, the elem named "data" of the frame*/
    int (*on_frame)(void *app_ctx, const uint8_t* data, size_t data_len, wish_protocol_peer_t* peer);
    /* Callback to be invoked when peer comes online */
    int (*on_online)(void *app_ctx, wish_protocol_peer_t* peer);
    /* Callback to be invoked when peer goes offline */
    int (*on_offline)(void *app_ctx, wish_protocol_peer_t* peer);
    /** This is the application context that will be supplied to every
     * invocation of the protocol handler callback functions. 
     * It must be initialised when saving the function contexts. */
    void *app_ctx;
} wish_protocol_handler_t;

/**
 * Append peer to bson document
 * 
 * Appends luid, ruid, rhid, rsid, protocol and online from given peer
 * 
 * If name is null the produced structure is 
 * 
 *     { luid, ruid, rhid, rsid, protocol, online }
 * 
 * if a name is given:
 * 
 *     name: { luid, ruid, rhid, rsid, protocol, online }
 * 
 * 
 * @param b
 * @param name_or_null
 * @param peer
 * @return 
 */
int bson_append_peer(bson *b, const char *name_or_null, const wish_protocol_peer_t* peer);

#ifdef __cplusplus
}
#endif

