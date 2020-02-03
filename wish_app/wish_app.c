#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "mbedtls/sha256.h"
#include "ed25519.h"

#include "wish_platform.h"
#include "wish_rpc.h"
#include "wish_app.h"
#include "wish_protocol.h"
#include "wish_debug.h"
#include "app_service_ipc.h"
#include "bson.h"
#include "bson_visit.h"


static wish_app_t apps[NUM_WISH_APPS];


//wish_rpc_client_t core_rpc_client;

static wish_app_t * wish_app_get_new(void) {
    int i = 0;

    for (i = 0; i < NUM_WISH_APPS; i++) {
        if (apps[i].occupied == false) {
            return &(apps[i]);
        }
    }
    /* Reached only if no free context was found */
    WISHDEBUG(LOG_CRITICAL, "Cannot get new Wish app context");
    return NULL;
}

wish_app_t * wish_app_find_by_wsid(uint8_t wsid[WISH_WSID_LEN]) {
    wish_app_t *retval = NULL;
    int i = 0;
    for (i = 0; i < NUM_WISH_APPS; i++) {
        if (apps[i].occupied == false) {
            continue;
        }
        if (memcmp(apps[i].wsid, wsid, WISH_WSID_LEN) == 0) {
            /* Found the proper app */
            retval = &(apps[i]);
            break;
        }
    }
    return retval;
}

bool wish_protocol_peer_populate_from_bson(wish_protocol_peer_t* peer, const uint8_t* buf) {
    bson_iterator it;
    
    bson_find_from_buffer(&it, buf, "luid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(peer->luid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "ruid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(peer->ruid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rhid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(peer->rhid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "rsid");
    if (bson_iterator_type(&it) != BSON_BINDATA)    { return false; }
    if (bson_iterator_bin_len(&it) != WISH_UID_LEN) { return false; }
    memcpy(peer->rsid, bson_iterator_bin_data(&it), WISH_UID_LEN);
    
    bson_find_from_buffer(&it, buf, "protocol");
    if (bson_iterator_type(&it) != BSON_STRING)     { return false; }
    if (bson_iterator_string_len(&it) >= WISH_PROTOCOL_NAME_MAX_LEN) { return false; }
    strncpy(peer->protocol, bson_iterator_string(&it), WISH_PROTOCOL_NAME_MAX_LEN);

    bson_find_from_buffer(&it, buf, "online");
    if (bson_iterator_type(&it) == BSON_BOOL) {
        peer->online = bson_iterator_bool(&it);
    } else {
        peer->online = false;
    }

    return true;
}

/** Set this to 1 if you want to drop frames from non-exposed peers */
#define DROP_FRAME_FROM_UNKNOWN_PEER 0
/** Set this to 1 if you want to drop frames from peers that are marked offline */
#define DROP_FRAME_FROM_OFFLINE_PEER 0


void wish_app_on_frame(wish_app_t* app, const uint8_t* frame, size_t frame_len) {
    bson_iterator it;
    
    if (bson_find_from_buffer(&it, frame, "peer") != BSON_OBJECT) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get peer from frame");
        return;
    }
    
    const uint8_t *peer_doc = bson_iterator_value(&it);

    bson_iterator_from_buffer(&it, frame);
    
    if (bson_find_fieldpath_value("peer.protocol", &it) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get protocol elem from peer");
        return;
    }
    
    const char *protocol_name = bson_iterator_string(&it);
    int32_t protocol_len = bson_iterator_string_len(&it);

    if (bson_find_from_buffer(&it, frame, "data") != BSON_BINDATA) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get data from frame");
        return;
    }

    const uint8_t* data = bson_iterator_bin_data(&it);
    int32_t data_len = bson_iterator_bin_len(&it);

    /* We now know the protocol, lets lookup the protocol handler */

    wish_protocol_handler_t* protocol = NULL;
    
    int i = 0;
    for (i = 0; i < app->num_protocols; i++) {
        if (strncmp(app->protocols[i]->protocol_name, protocol_name, WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
            /* Found protocol handler */
            if (app->protocols[i]->on_frame != NULL) {
                //WISHDEBUG(LOG_CRITICAL, "Calling protocol handler");
                //WISHDEBUG(LOG_CRITICAL, "calling on_frame for %s with payload len: %d", protocol_name, data_len);
                protocol = app->protocols[i];
            }
            else {
                WISHDEBUG(LOG_CRITICAL, "Protocol handler is null!");
            }
            break;
        }
    }
    
    if(protocol) {
        wish_protocol_peer_t peer;
        // protocol handler found, get peer
        bool success = wish_protocol_peer_populate_from_bson(&peer, peer_doc);

        if (!success) {
            bson_visit("Failed populating peer from:", peer_doc);
            return;
        }
        protocol->on_frame(protocol->app_ctx, data, data_len, &peer);
    } else {
        bson_visit("No protocol handler for", data);
    }
}

/** Callback invoked when core has determined a change in the peer's
 * status */
void wish_app_on_peer(wish_app_t *app, const uint8_t *peer_doc) {
    //WISHDEBUG(LOG_CRITICAL, "Peer information to app");
    //bson_visit(peer_doc, elem_visitor);

    bson_iterator it;
    
    if (bson_find_from_buffer(&it, peer_doc, "protocol") != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get protocol elem from peer");
        return;
    }
    
    const char *protocol_name = bson_iterator_string(&it);

    bool protocol_online = false;
    
    if (bson_find_from_buffer(&it, peer_doc, "online") == BSON_BOOL) {
        protocol_online = bson_iterator_bool(&it);
    }
    
    /* We now know the protocol, lets lookup the protocol handler */

    wish_protocol_handler_t* protocol = NULL;
    
    int i = 0;
    for (i = 0; i < app->num_protocols; i++) {
        if (strncmp(app->protocols[i]->protocol_name, protocol_name, WISH_PROTOCOL_NAME_MAX_LEN) == 0) {
            /* Found protocol handler */
            if (app->protocols[i]->on_online != NULL || app->protocols[i]->on_offline != NULL) {
                protocol = app->protocols[i];
            } else {
                WISHDEBUG(LOG_CRITICAL, "There is no handler for online or offline messages for protocol %s, on: %p, off: %p", protocol_name, app->protocols[i]->on_online, app->protocols[i]->on_offline);
            }
            break;
        }
    }
    
    if(protocol) {
        // protocol handler found, get peer
        wish_protocol_peer_t peer;
        bool success = wish_protocol_peer_populate_from_bson(&peer, peer_doc);
        
        if(!success) { return; }
        
        if(protocol_online) {
            protocol->on_online(protocol->app_ctx, &peer);
        } else {
            protocol->on_offline(protocol->app_ctx, &peer);
        }
    }
}

static void host_config_cb(struct wish_rpc_entry* req, void* ctx, const uint8_t* data, size_t data_len) {
    //bson_visit("Got host_config:", data);
    wish_app_t *app = (wish_app_t *)req->cb_context;
    
    bson_iterator it;
    BSON_ITERATOR_FROM_BUFFER(&it, data);
    
    bson_find_fieldpath_value("data.hid", &it);
    if (bson_iterator_type(&it) == BSON_BINDATA) {
        const char* whid = bson_iterator_bin_data(&it);
        memcpy(app->whid, whid, WISH_WHID_LEN); 
    }
}

/** Callback invoked when service is connected to core */
void wish_app_on_ready(wish_app_t *app) {
    WISHDEBUG(LOG_DEBUG, "Ready signal to app");
    size_t buf_len = 100;
    uint8_t buf[buf_len];
    memset(buf, 0, buf_len);
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_bool(&bs, "ready", true);
    bson_finish(&bs);
    
    send_app_to_core(app->wsid, bson_data(&bs), bson_size(&bs));
    if (app->ready != NULL) {
        app->ready_state = true;
        app->ready(app, true);
    }
    
    /* fetch local core's host id */
    bson host_config_bs;
    bson_init_buffer(&host_config_bs, buf, buf_len);
    bson_append_string(&host_config_bs, "op", "host.config");
    bson_append_start_array(&host_config_bs, "args");
    bson_append_finish_array(&host_config_bs);
    bson_append_int(&host_config_bs, "id", 0);
    bson_finish(&host_config_bs);

    wish_app_request(app, &host_config_bs, host_config_cb, app);
}

static void send(void* ctx, uint8_t* buf, int len) {
    wish_app_t* app = ctx;
    send_app_to_core(app->wsid, buf, len);
}

/** 
 * Create a wish application
 *
 * Returns the wish_app instance which was just created, or NULL if
 * error
 */
wish_app_t * wish_app_create(const char *app_name) {

    uint8_t app_wsid[WISH_ID_LEN];

    if (wish_app_get_wsid(app_name, app_wsid)) {
        WISHDEBUG(LOG_CRITICAL, "Cannot get wsid for %s", app_name);
        return NULL;
    }

    wish_debug_print_array(LOG_DEBUG, "wish_app_create", app_wsid, WISH_ID_LEN);

    wish_app_t *app = wish_app_get_new();
    if (app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Fresh app context is null!");
        return NULL;
    }

    app->occupied = true;
    memcpy(app->wsid, app_wsid, WISH_WSID_LEN);
    strncpy(app->name, app_name, WISH_APP_NAME_MAX_LEN);
    /* Ensure null termination: */
    app->name[WISH_APP_NAME_MAX_LEN-1] = 0;
    
    app->rpc_client.send = send;
    app->rpc_client.send_ctx = app;
    app->rpc_client.name = "wish_app.c:WishApp::WishCoreRpcClient";

    return app;
}


/* Login:
 * App to core: { name: 'Chat CLI',
 *   protocols: [ 'chat' ],
 *     permissions: [ 'identity.list', 'services.listPeers' ] }
 */
void wish_app_login(wish_app_t *app) {
    
    int i = 0;

    const size_t login_msg_max_len = 255;
    uint8_t login_msg[login_msg_max_len];
    
    bson bs;
    bson_init_buffer(&bs, login_msg, login_msg_max_len);
    bson_append_binary(&bs, "wsid", app->wsid, WISH_WSID_LEN);
    bson_append_string(&bs, "name", app->name);
    bson_append_start_array(&bs, "protocols");

    #define NBUFL 8
    uint8_t pbuf[NBUFL];
    for (i = 0; i < app->num_protocols; i++) {
        bson_numstrn(pbuf, NBUFL, i);
        bson_append_string(&bs, pbuf, app->protocols[i]->protocol_name);
    }

    bson_append_finish_array(&bs);
    bson_append_start_array(&bs, "permissions");

    /* requesting permissions not yet supported
    for (i = 0; i < app->num_permissions; i++) {
        bson_numstrn((char *)nbuf, NBUFL, i);
        bson_append_string(&bs, nbuf, *(app->permissions[i]));
    }
    */
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //bson_visit(login_msg, elem_visitor);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error in wish_app_create");
    }
    
    send_app_to_core(app->wsid, login_msg, bson_size(&bs));
    
    /*
     * RPC app to core { op: 'identity.list', id: 1 }
     */

    /* Then, upon RPC reply: 
     *
     * App to core: { ready: true }
     */
}

void wish_app_add_protocol(wish_app_t *app, wish_protocol_handler_t *handler) {
    /* Set up protocols */
    if (app->num_protocols < WISH_APP_MAX_PROTOCOLS) {
        app->protocols[app->num_protocols] = handler;
        // WishApp: Added protocol %s at index %d", handler->protocol_name, app->num_protocols
        app->num_protocols++;
    } else {
        WISHDEBUG(LOG_CRITICAL, "WishApp: Error adding protocol %s, memory full.", handler->protocol_name);
    }
}

/**
 * Disconnect a Wish app from the core, release app context
 * @param app pointer to app context object to be deleted
 */
void wish_app_destroy(wish_app_t *app) {
    WISHDEBUG(LOG_CRITICAL, "in wish_app_destroy");
}



/**
 * Get WSID correspoinding to app_name, storing it to array wsid
 *
 * Returns 0 on success
 */
int wish_app_get_wsid(const char* app_name, uint8_t wsid[WISH_ID_LEN]) {
#if 0
    /* Just generate a wsid by first hashing the app name (to form 32
     * bytes), which is used as seed to ed25519 create keypair - note
     * that under this scheme the wsid will always be the same for any 
     * given app_name string. */
    mbedtls_sha256_context sha256_ctx;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); 
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *)app_name, 
        strnlen(app_name, WISH_APP_NAME_MAX_LEN)); 
    uint8_t seed[WISH_ED25519_SEED_LEN];
    mbedtls_sha256_finish(&sha256_ctx, seed);
    mbedtls_sha256_free(&sha256_ctx);

    uint8_t service_pubkey[WISH_PUBKEY_LEN];
    uint8_t service_privkey[WISH_PRIVKEY_LEN];
    ed25519_create_keypair(service_pubkey, service_privkey, seed);
#endif

    memset(wsid, 0, WISH_ID_LEN);
    strncpy(wsid, app_name, WISH_ID_LEN);
    return 0;
}


void wish_app_determine_handler(wish_app_t* app, const uint8_t* data, size_t len) {
    bson_iterator it;
    
    const char* type_str = NULL;
    int type_str_len = 0;
    
    if (bson_find_from_buffer(&it, data, "type") == BSON_STRING) {
        type_str = bson_iterator_string(&it);
        type_str_len = bson_iterator_string_len(&it);
    }
    
    if (type_str) {
        if (strncmp(type_str, "signal", type_str_len) == 0) {
            /* Is a signal */
            
            if (bson_find_from_buffer(&it, data, "signal") != BSON_STRING) {
                WISHDEBUG(LOG_CRITICAL, "Invalid signal type.");
                return;
            }
            
            const char* signal_str = bson_iterator_string(&it);
            int32_t signal_str_len = bson_iterator_string_len(&it)
                    ;
            if (strncmp(signal_str, "ready", signal_str_len) == 0) {
                /* Ready signal */
                wish_app_on_ready(app);
            } else if (strncmp(signal_str, "quarantine", signal_str_len) == 0) {
                WISHDEBUG(LOG_CRITICAL, "We ended up in Ellis island. (Quarantined!)");
            } else {
                WISHDEBUG(LOG_CRITICAL, "Unrecognized signal from core");
            }
        } else if (strncmp(type_str, "peer", type_str_len) == 0) {
            if (bson_find_from_buffer(&it, data, "peer") != BSON_OBJECT) {
                WISHDEBUG(LOG_CRITICAL, "Failed to get peer info doc");
                return;
            }

            wish_app_on_peer(app, bson_iterator_value(&it));
        } else if (strncmp(type_str, "frame", type_str_len) == 0) {
            /* Frame */
            wish_app_on_frame(app, data, len);
        }
    } else {
        int32_t ack = 0, err = 0;
        //WISHDEBUG(LOG_CRITICAL, "No type in core to app, len=%d", len);
        //bson_visit(data, elem_visitor);

        if (bson_find_from_buffer(&it, data, "ack") == BSON_INT
            || bson_find_from_buffer(&it, data, "err") == BSON_INT
            || bson_find_from_buffer(&it, data, "sig") == BSON_INT
            || bson_find_from_buffer(&it, data, "fin") == BSON_INT) 
        {
            bson bs;
            bson_init_with_data(&bs, data);
            /* I recon this is an RPC request reply, an ack or err to a
             * request that we sent using wish_app_send! */
            if (rpc_client_receive(&app->rpc_client, NULL, bson_data(&bs), bson_size(&bs))) {
                WISHDEBUG(LOG_CRITICAL, "RPC Client did not find a matching request.");
            }
        }
        else {
            //No ack, err or fin in reponse!
            bson_visit("No ack, err or fin in reponse!", data);
        }
    }
}

static void wish_app_send_cb(struct wish_rpc_entry* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    //WISHDEBUG(LOG_CRITICAL, "wish_app_send_cb");
}

rpc_id wish_app_send_context(wish_app_t* app, wish_protocol_peer_t* peer, const uint8_t* buffer, size_t len, rpc_client_callback cb, void* cb_context) {
    
    if (peer == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_app_send: peer is NULL.");
        return 0;
    }
    
    if (cb == NULL) { cb = wish_app_send_cb; }

    // Call send_app_to_core as in app.js:send, like this:
    // this.coreClient.rpc('services.send', [peer, payload], cb);

    int args_len = 0;
    int frame_len_max = len + 512;
    uint8_t args[frame_len_max];
    
    bson bs;
    bson_init_buffer(&bs, args, frame_len_max);
    bson_append_string(&bs, "op", "services.send");
    bson_append_start_array(&bs, "args");
    bson_append_start_object(&bs, "0");
    bson_append_binary(&bs, "luid", peer->luid, WISH_UID_LEN);
    bson_append_binary(&bs, "ruid", peer->ruid, WISH_UID_LEN);
    bson_append_binary(&bs, "rhid", peer->rhid, WISH_UID_LEN);
    bson_append_binary(&bs, "rsid", peer->rsid, WISH_UID_LEN);
    bson_append_string(&bs, "protocol", peer->protocol);
    bson_append_finish_object(&bs);
    bson_append_binary(&bs, "1", buffer, len);
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", 0);
    bson_finish(&bs);
    
    if (bs.err) { WISHDEBUG(LOG_CRITICAL, "4 bson_error: %i %s", bs.err, bs.errstr); return 0; }
    
    rpc_client_req* creq = rpc_client_request(&app->rpc_client, &bs, cb, cb_context);
    
    if (creq == NULL) { WISHDEBUG(LOG_CRITICAL, "wish_app_send: Failed creating services.send request"); return 0; }
    
    int id = creq->id;
    send_app_to_core(app->wsid, bson_data(&bs), bson_size(&bs));
    
    return id;
}

rpc_id wish_app_send(wish_app_t* app, wish_protocol_peer_t* peer, const uint8_t* buffer, size_t len, rpc_client_callback cb) {
    return wish_app_send_context(app, peer, buffer, len, cb, NULL);
}


/*

Call send_app_to_core as in app.js:send, like this:
this.coreClient.rpc(op, args, cb);

Usage:

    void identity_list_cb(void *ctx, rpc_id id, uint8_t *payload, size_t payload_len) {
        WISHDEBUG(LOG_CRITICAL, "response to identity_list request: wish_app_core %i", payload_len);
        bson_visit(payload, elem_visitor);
    }
   
    bson bs; 
    bson_init(&bs);
    bson_append_start_array(&bs, "args");
    bson_append_bool(&bs, "0", true);
    bson_append_string(&bs, "1", "complex");
    bson_append_int(&bs, "2", 2);
    bson_append_start_object(&bs, "3");
    bson_append_string(&bs, "complex", "trem");
    bson_append_finish_object(&bs);
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    bson_iterator it;
    bson_find_from_buffer(&it, bs.data, "args");
    
    // init an iterator to the first element in the bson array value, skip first 
    //   4 bytes, it contains total length of content
    char* args = (char*)(bson_iterator_value(&it) + 4);
    const char* p0 = it.cur;
    bson_iterator_next(&it);
    int size = (int)(it.cur - p0);

    WISHDEBUG(LOG_CRITICAL, "wish_app_core %i", size);
    bson_visit(args, elem_visitor);
    
    wish_app_core(app, "identity.list", args, size, identity_list_cb);
  
*/

rpc_client_req* wish_app_request(wish_app_t* app, bson* req, rpc_client_callback cb, void* cb_ctx) {
    rpc_client_req* client_req = rpc_client_request(&app->rpc_client, req, cb, cb_ctx);
    
    if (client_req == NULL) { WISHDEBUG(LOG_CRITICAL, "wish_app_request failed"); }
    
    send_app_to_core(app->wsid, bson_data(req), bson_size(req));
    
    return client_req;
}

void wish_app_cancel(wish_app_t *app, rpc_client_req *req) {
    rpc_client_end_by_id(&app->rpc_client, req->id);
}

void wish_app_send_app_to_core(wish_app_t* app, const uint8_t* frame, int frame_len) {
    send_app_to_core(app->wsid, frame, frame_len);
}

void wish_app_connected(wish_app_t *app, bool connected) {
    if (connected) {
        //WISHDEBUG(LOG_CRITICAL, "App is connected");
        wish_app_login(app);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "App is disconnected!");
        app->ready_state = false;
        if (app->ready != NULL) {
            app->ready(app, app->ready_state);
        }
    }
}

void wish_app_periodic(wish_app_t* app) {
    if(app->periodic != NULL) {
        app->periodic(app->periodic_ctx);
    }
}

rpc_client_req* wish_app_request_passthru(wish_app_t* app, const bson* req, rpc_client_callback cb, void* ctx) {
    rpc_client_req* creq = rpc_client_passthru(&app->rpc_client, req, cb, ctx);
    return creq;
}

void wish_core_request_cancel(wish_app_t* app, int id) {
    rpc_client_passthru_end_by_id(&app->rpc_client, id);
}

