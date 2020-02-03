#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "bson.h"
#include "utlist.h"
#include "wish_debug.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "app.h"

#include "bson_visit.h"

app_t* apps;

app_t* app_get_new_context(void) {
    app_t* app = (app_t*) calloc(1, sizeof(app_t));
    
    LL_APPEND(apps, app);
    
    return app;
}

static int online(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "online %p luid: %02x %02x %02x %02x ruid:  %02x %02x %02x %02x", peer, peer->luid[0], peer->luid[1], peer->luid[2], peer->luid[3], peer->ruid[0], peer->ruid[1], peer->ruid[2], peer->ruid[3]);
    
    app_t *app = app_ctx;
    
    if(app->online != NULL) {
        app->online(app_ctx, peer);
    }

    return 0;
}

static int offline(void *app_ctx, wish_protocol_peer_t* peer) {
    //WISHDEBUG(LOG_CRITICAL, "offline %p", peer);

    app_t *app = app_ctx;
    
    if(app->offline != NULL) {
        app->offline(app_ctx, peer);
    }
    
    return 0;
}

static int frame(void* app_ctx, const uint8_t *data, size_t data_len, wish_protocol_peer_t* peer) {
    app_t *app = app_ctx;

    if(app->frame != NULL) {
        app->frame(app_ctx, data, data_len, peer);
    }

    return 0;
}

void send_to_peer_cb(struct wish_rpc_entry* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    WISHDEBUG(LOG_CRITICAL, "send_to_peer_cb called.");
}

// expect ctx to be app_peer_t, and send data to the peer of this app. This will
// call services.send and send in case of a remote device
static void send_to_peer(void* ctx, uint8_t* buf, int buf_len) {
    app_peer_t* app_peer = ctx;    
    wish_app_send(app_peer->app, app_peer->peer, buf, buf_len, send_to_peer_cb);
}

//#define REQUEST_POOL_SIZE 10
//static rpc_server_req request_pool[REQUEST_POOL_SIZE];

/**
 * Create WishApp
 * 
 * @return 
 */
app_t* app_init() {
    app_t* app = app_get_new_context();
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not instantiate new Wish App!");
        return NULL;
    }

    // set a default name, override using mist_set_name
    strncpy(app->name, "WishApp", APP_NAME_MAX_LEN);

    memcpy(app->protocol.protocol_name, "social", WISH_PROTOCOL_NAME_MAX_LEN);

    app->protocol.on_online = online,
    app->protocol.on_offline = offline,
    app->protocol.on_frame = frame,
    app->protocol.app_ctx = app; /* Saved here so that the online, frame callbacks will receive the appropriate app context */
    app->protocol.rpc_client.send = send_to_peer;
    app->protocol.rpc_client.name = "WishApp.protocol.rpc_client";
    
    return app;
}

rpc_id app_respond(app_t* app, wish_protocol_peer_t* peer, uint8_t* response, size_t response_len, rpc_client_callback cb) {
    WISHDEBUG(LOG_DEBUG, "app_respond");

    /** The RPC id of the message which is sent down */
    rpc_id id = -1;
    
    id = wish_app_send(app->app, peer, response, response_len, cb);
    
    if (id <= 0) { WISHDEBUG(LOG_CRITICAL, "Wish app send fail"); }
    
    WISHDEBUG(LOG_DEBUG, "exiting receive_device_southbound");
    return id;
}

rpc_id app_request(app_t* app, wish_protocol_peer_t* peer, uint8_t* request, size_t request_len, rpc_client_callback cb) {
    bson req;
    bson_init_with_data(&req, request);
    
    rpc_client_request(&app->protocol.rpc_client, &req, cb, NULL);

    wish_app_send(app->app, peer, bson_data(&req), bson_size(&req), NULL);
    
    return 0;
}

app_t* app_lookup_by_wsid(uint8_t* wsid) {
    app_t* app = NULL;
    
    LL_FOREACH(apps, app) {
        if (memcmp(app->app->wsid, wsid, WISH_WSID_LEN) == 0) {
            return app;
            break;
        }
    }

    return app;
}
