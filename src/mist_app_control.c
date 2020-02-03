/**
 * Copyright (C) 2020, ControlThings Oy Ab
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * @license Apache-2.0
 */
#include "mist_app_control.h"
#include "mist_app.h"
#include "mist_follow.h"
#include "mist_mapping.h"
#include "string.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_port_config.h"
#include "wish_debug.h"

void handle_control_model(rpc_server_req *req, const uint8_t* args) {
    mist_app_t *mist_app = (mist_app_t *)req->context;

    bson bs;
#ifdef MIST_CONTROL_MODEL_BUFFER_FROM_HEAP
    bson_init(&bs);
#else
    /* This defines the maximum model size in bytes */
    size_t data_doc_max_len = WISH_PORT_RPC_BUFFER_SZ;
    uint8_t data_doc[data_doc_max_len];
    bson_init_buffer(&bs, data_doc, data_doc_max_len);
#endif
    
    bson_append_start_object(&bs, "data");
    model_generate_bson(&(mist_app->model), &bs);
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "BSON error %d in handle control model", bs.err);
        rpc_server_error_msg(req, 999, "BSON error in handle_control_model");
    } else {
        WISHDEBUG(LOG_CRITICAL, "BSON size is %d", bson_size(&bs));
        rpc_server_send(req, (uint8_t *) bson_data(&bs), bson_size(&bs));
    }
#ifdef MIST_CONTROL_MODEL_BUFFER_FROM_HEAP
    bson_destroy(&bs);
#endif
}

static void control_follow_end(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "control_follow_end req->id: %i", req->id);
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_control_follow(rpc_server_req* req, const uint8_t* args) {
    mist_app_t* mist_app = req->context;
    mist_model *model = &(mist_app->model);

    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t));
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    
    req->end = control_follow_end;
    
    /* Now, send one "follow" reply for each endpoint, for initial syncing. */

    mist_ep* curr_ep = model->endpoints;

    while (curr_ep != NULL) {

        if (curr_ep->readable && curr_ep->read != NULL) {
            mist_internal_read(mist_app, curr_ep, req);
            //generate_mist_follow_msg(mist_app, req, curr_ep);
        }

        if (curr_ep->child != NULL) {
            curr_ep = curr_ep->child;
            continue;
        }

        if (curr_ep->next != NULL) {
            curr_ep = curr_ep->next;
            continue;
        }

        if (curr_ep->parent == NULL) {
            curr_ep = NULL;
        } else {
            while (curr_ep->parent != NULL) {
                curr_ep = curr_ep->parent;

                if (curr_ep->next != NULL) {
                    curr_ep = curr_ep->next;
                    break;                   
                } else if (curr_ep->parent == NULL) {
                    curr_ep = NULL;
                    break;
                }
            }
        }
    }
}

static void control_read_end(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "control_read_end req->id: %i", req->id);
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_control_read(rpc_server_req *req, const uint8_t* args) {
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);
    
    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t)); /* Will be free'ed in control_read_end */
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    req->end = control_read_end;

    bson_iterator it;
    
    if (bson_find_from_buffer(&it, args, "0") != BSON_STRING) {
        rpc_server_error_msg(req, 104, "Endpoint not string.");
        return;
    }
    
    const char* endpoint = bson_iterator_string(&it);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        rpc_server_error_msg(req, 104, "Endpoint not found or permission denied.");
        //WISHDEBUG(LOG_CRITICAL, "control.read: Could not find endpoint %s, aborting!", endpoint);
        return;
    }

    if(!ep->readable) {
        rpc_server_error_msg(req, 569, "Endpoint not readable.");
        return;
    }
    
    if (ep->read == NULL) {
        rpc_server_error_msg(req, 569, "Endpoint read function not implemented.");
        return;
    }

    ep->read(ep, peer, req->sid);
}

static void control_write_end(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "control_write_end req->id: %i", req->id);
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_control_write(rpc_server_req *req, const uint8_t* args) {
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);
    
    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t)); /* Will be free'ed in control_write_end */
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    req->end = control_write_end;

    bson_iterator it;
    
    if (bson_find_from_buffer(&it, args, "0") != BSON_STRING) {
        rpc_server_error_msg(req, 104, "Endpoint not string.");
        return;
    }
    
    const char* endpoint = bson_iterator_string(&it);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        WISHDEBUG(LOG_DEBUG, "control.write: Could not find endpoint %s, aborting!", endpoint);
        rpc_server_error_msg(req, 104, "Endpoint not found or permission denied.");
        return;
    }
    if ( !ep->writable ) {
        WISHDEBUG(LOG_DEBUG, "control.write: Endpoint %s not writable, aborting!", endpoint);
        rpc_server_error_msg(req, 105, "Endpoint not writable or permission denied.");
        return;
    }
    if (!ep->write) {
        WISHDEBUG(LOG_DEBUG, "control.write: Endpoint %s has not write function registered!", endpoint);
        rpc_server_error_msg(req, 105, "Endpoint not writable or permission denied.");
        return;
    }

    bson_find_from_buffer(&it, args, "1");
    
    bson in_args;
    bson_init_with_data(&in_args, args);
    
    bson bs;
    size_t buf_len = bson_size(&in_args)+200;
    uint8_t buf[buf_len];
    bson_init_buffer(&bs, buf, buf_len);

    if (bson_iterator_type(&it) == BSON_EOO) {
        bson_append_null(&bs, "args");
    } else {
        
        // Work out the data type to write
        bson_type type = bson_iterator_type(&it);

        if (ep->type == MIST_TYPE_FLOAT) {
            switch (type) {
                case BSON_DOUBLE:
                    bson_append_double(&bs, "args", bson_iterator_double(&it));
                    break;
                case BSON_INT:
                    bson_append_double(&bs, "args", bson_iterator_int(&it));
                    break;
                default:
                    WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, type);
                    rpc_server_error_msg(req, 105, "Data type not supported for float endpoint");
                    return;
            }
        } else if (ep->type == MIST_TYPE_BOOL) {
            switch (type) {
                case BSON_DOUBLE:
                    bson_append_bool(&bs, "args", bson_iterator_double(&it) == 0 ? false : true);
                    break;
                case BSON_INT:
                    bson_append_bool(&bs, "args", bson_iterator_int(&it) == 0 ? false : true);
                    break;
                case BSON_BOOL:
                    bson_append_bool(&bs, "args", bson_iterator_bool(&it));
                    break;
                default:
                    WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, type);
                    rpc_server_error_msg(req, 105, "Data type not supported for bool endpoint");
                    return;
            }
        } else if (ep->type == MIST_TYPE_INT) {
            switch (type) {
                case BSON_DOUBLE:
                    bson_append_int(&bs, "args", (int) bson_iterator_double(&it));
                    break;
                case BSON_INT:
                    bson_append_int(&bs, "args", bson_iterator_int(&it));
                    break;
                default:
                    WISHDEBUG(LOG_DEBUG, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, type);
                    rpc_server_error_msg(req, 105, "Data type not supported.");
                    return;
            }
        } else if (ep->type == MIST_TYPE_STRING) {
            switch (type) {
                case BSON_STRING:
                    bson_append_string(&bs, "args", bson_iterator_string(&it));
                    break;
                default:
                    WISHDEBUG(LOG_CRITICAL, "Write %s: Can't handle BSON datatype %d\n\r", endpoint, type);
                    rpc_server_error_msg(req, 79, "Cannot write such bson type to string endpoint.");
                    return;
            }
        } else {
            WISHDEBUG(LOG_CRITICAL, "Write %s: MIST_TYPE of endpoint is not handeled %d\n\r", endpoint, type);
            rpc_server_error_msg(req, 79, "Cannot write to endpoint.");
            return;
        }
    }
    
    bson_finish(&bs);

    enum mist_error err = ep->write(ep, peer, req->sid, &bs);
}

static void control_invoke_end(rpc_server_req* req) {
    //WISHDEBUG(LOG_CRITICAL, "control_invoke_end req->id: %i", req->id);
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_control_invoke(rpc_server_req *req, const uint8_t* args) {
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);
    
    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t)); /* Will be free'ed in control_invoke_end */
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    req->end = control_invoke_end;

    bson_iterator it;

    if (bson_find_from_buffer(&it, args, "0") != BSON_STRING) {
        rpc_server_error_msg(req, 104, "Endpoint not string.");
        return;
    }
    
    bson in_args;
    bson_init_with_data(&in_args, args);
    
    const char* endpoint = bson_iterator_string(&it);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        rpc_server_error_msg(req, 105, "Endpoint not found.");
        return;
    }
    if ( !ep->invokable ) {
        rpc_server_error_msg(req, 105, "Endpoint not invokable.");
        return;
    }
    if (ep->invoke == NULL) {
        rpc_server_error_msg(req, 105, "Endpoint not invokable (no function).");
        return;
    }

    bson_find_from_buffer(&it, args, "1");

    bson bs;
    size_t buf_len = bson_size(&in_args)+200;
    uint8_t buf[buf_len];
    bson_init_buffer(&bs, buf, buf_len);

    if (bson_iterator_type(&it) == BSON_EOO) {
        bson_append_null(&bs, "args");
    } else {
        bson_append_element(&bs, "args", &it);
    }
    
    bson_finish(&bs);

    ep->invoke(ep, peer, req->sid, &bs);
}

/*
map: function(req, res, context) { 
    var srcEpid = req.args[0]; // axis1
    var srcOpts = req.args[1];
    var dstEpid = req.args[2];

    var dstUrl = 'wish://'+context.peer.luid+'>'+context.peer.ruid+'@'+context.peer.rhid+'/'+context.peer.rsid;
    var key = crypto.createHash('sha1').update(JSON.stringify(req)).digest('hex').substr(0, 8);

    var settings = { 
        epid: dstEpid, 
        url: dstUrl, 
        opts: srcOpts };

    self.map(key, srcEpid, settings, { peer: context.peer }, function(err, data) {
        if (err) { return res.error(data); }
        res.send(data);
    });
},
*/

void handle_control_map(rpc_server_req *req, const uint8_t* args) {
    WISHDEBUG(LOG_CRITICAL, "Control map");
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);

    bson_iterator it;
    
    bson_find_from_buffer(&it, args, "0");
    char* src_epid = (char*)bson_iterator_string(&it);

    bson_find_from_buffer(&it, args, "1");
    char* src_opts = (char*)bson_iterator_value(&it);

    bson_find_from_buffer(&it, args, "2");
    char* dst_epid = (char*)bson_iterator_string(&it);
    
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, src_epid, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.invoke: Could not find endpoint %s, aborting!", src_epid);
        return;
    }
    if ( !ep->readable ) {
        WISHDEBUG(LOG_CRITICAL, "control.map: Endpoint %s not readable, aborting!", src_epid);
        return;
    }

    bson_visit("control.map arguments:", args);

    int buffer_len = 400;
    uint8_t buffer[buffer_len];

    bson b;
    bson_init_buffer(&b, buffer, buffer_len);
    
    // FIXME create unique mapping identifier (gobl) and store it along with opts and epids
    char mapping_id[MAPPING_ID_LEN] = { 0 };
    wish_platform_sprintf(mapping_id, "m%i", mist_mapping_get_new_id((mist_app_t*) req->context));
    bool mapping_ret = mist_mapping_save((mist_app_t*) req->context, (wish_protocol_peer_t *)req->ctx, mapping_id, src_epid, dst_epid);
    if (mapping_ret == false) {
        /* Making of the mapping failed! */
        WISHDEBUG(LOG_CRITICAL, "Cannot make the mapping!");
        rpc_server_error_msg(req, 99, "Cannot map at this time.");
        return;
    }

    bson_append_string(&b, "data", mapping_id);
    bson_finish(&b);

    // Mapping made, sending response to map requestor.
    rpc_server_send(req, buffer, buffer_len);
}

/*
requestMapping: function(req, res, context) {
    // add ACL checks here
    var key = crypto.createHash('sha1').update(JSON.stringify(req)).digest('hex').substr(0, 8);

    var from = req.args[0];     // j
    var fromEpid = req.args[1]; // axis1
    var fromOpts = req.args[2]; // { type: 'direct', interval: 'change' }
    var toEpid = req.args[3];   // vibrateStrong
    var toOpts = req.args[4];   // { type: 'write' }

    //d.control.requestMapping(j, 'axis1', { type: 'direct', interval: 'change' }, 'vibrateStrong', { type: 'write' });

    from.luid = context.peer.luid;
    if (from.rhid === 'localhost'){
        from.rhid = context.peer.rhid;
    }            
    var url = 'wish://'+from.luid+'>'+from.ruid+'@'+from.rhid+'/'+from.rsid; 
    var peer = { luid: from.luid, ruid: from.ruid, rhid: from.rhid, rsid: from.rsid };

    //j.control.map('axis1', { type: 'direct', interval: 'change' }, 'vibrateStrong', function(err, key) {})
    self.ucp.request(peer, 'control.map', [fromEpid, fromOpts, toEpid], function(err, key) {
        if (err) { return res.error(key); }
        //console.log("control map response(err,data):", err, key);

        var settings = {
            epid: fromEpid,
            url: url,
            opts: toOpts };

        // key, toEpid, toOpts
        self.map(key, toEpid, settings, { peer: context.peer }, function (err, data) {
            res.send(data);
        });
    });
},        
*/

void handle_control_map_response(rpc_client_req* req, void* context, const uint8_t* payload, size_t payload_len) {
    rpc_server_req *orig_req = req->cb_context;
    //WISHDEBUG(LOG_CRITICAL, "control.requestMapping got response from map request and has context pointer %p", req->cb_context);
    //bson_visit("control.requestMapping got response from map", payload);
    
    bson_iterator res;
    bson_find_from_buffer(&res, payload, "data");
    if (bson_iterator_type(&res) != BSON_STRING) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping got invalid response from map request");
        rpc_server_error_msg(orig_req, 13, "Invalid response from map request.");
        return;
    }
    
    int buffer_len = 400;
    uint8_t buffer[buffer_len];
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    
    bson_append_element(&bs, "data", &res);
    
    bson_finish(&bs);
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL,  "BSON error in handle_control_map_response");
        rpc_server_error_msg(orig_req, 999,  "BSON error in handle_control_map_response");
    } else {
        //bson_visit("control.requestMapping sending back data to original requestor.", buffer);
        rpc_server_send(orig_req, bson_data(&bs), bson_size(&bs));
    }
}

void wish_app_send_mist_request_mapping_cb(rpc_client_req* req, void* context, const uint8_t* payload, size_t payload_len) {
    bson_visit("wish_app_send_mist_request_mapping_cb", payload);
    rpc_server_req *orig_req = req->cb_context;
    
    rpc_server_error_msg(orig_req, 311, "Failed sending.");
}

void handle_control_request_mapping(rpc_server_req *req, const uint8_t* args) {
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);

    // necessary to make copy?
    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t));
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    
    bson_iterator it;
    
    // signal source peer
    bson_find_from_buffer(&it, args, "0");
    if ( bson_iterator_type(&it) != BSON_OBJECT ) { return; }

    /* Create a BSON object from the peer document we got as args element "0" */
    bson peer_bs;
    bson_iterator_subobject(&it, &peer_bs);
    
    char* peer_ruid;
    char* peer_rhid;
    char* peer_rsid;
    char* peer_protocol;
   
    bson_find(&it, &peer_bs, "ruid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        rpc_server_error_msg(req, 67, "Invalid peer ruid.");
        return;
    }
    
    peer_ruid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "rhid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        rpc_server_error_msg(req, 67, "Invalid peer rhid.");
        return;
    }

    peer_rhid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "rsid");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != WISH_ID_LEN) {
        rpc_server_error_msg(req, 67, "Invalid peer rsid.");
        return;
    }

    peer_rsid = (char*) bson_iterator_bin_data(&it);
    
    bson_find(&it, &peer_bs, "protocol");
    
    if (bson_iterator_type(&it) != BSON_STRING || bson_iterator_string_len(&it) > WISH_PROTOCOL_NAME_MAX_LEN) {
        WISHDEBUG(LOG_CRITICAL, "Invalid peer protocol string: type: %i, len: %i\n", bson_iterator_type(&it), bson_iterator_string_len(&it));
        rpc_server_error_msg(req, 67, "Invalid peer protocol.");
        return;
    }

    peer_protocol = (char*) bson_iterator_string(&it);
    
    int buf_len = 300;
    char buf[buf_len];
    
    bson bs;
    bson_init_buffer(&bs, buf, buf_len);
    bson_append_binary(&bs, "luid", peer->luid, WISH_ID_LEN);
    bson_append_binary(&bs, "ruid", peer_ruid, WISH_ID_LEN);
    bson_append_binary(&bs, "rhid", peer_rhid, WISH_ID_LEN);
    bson_append_binary(&bs, "rsid", peer_rsid, WISH_ID_LEN);
    bson_append_string(&bs, "protocol", peer_protocol);
    bson_finish(&bs);
    
    
    if (bs.err) {
        WISHDEBUG(LOG_CRITICAL, "subobj peer bson ERROR: %i, %s", bs.err, bs.errstr);
    }
    
    //bson_visit("subobj peer:", (uint8_t*)bson_data(&peer_bs));
    //bson_visit("subobj peer (luid overwritten):", (uint8_t*)bson_data(&bs));
    
    wish_protocol_peer_t src_peer;
    bool success = wish_protocol_peer_populate_from_bson(&src_peer, (uint8_t*) bson_data(&bs));

    if (!success) {
        rpc_server_error_msg(req, 61, "Invalid source peer.");
        return;
    }

    // signal source epid
    bson_find_from_buffer(&it, args, "1");
    char* src_epid = (char*)bson_iterator_string(&it);

    // signal source opts
    bson_iterator src_opts;
    bson_find_from_buffer(&src_opts, args, "2");
    //WISHDEBUG(LOG_CRITICAL, "Src opts bson type in requestMapping %i", bson_iterator_type(&src_opts));

    // signal destination epid
    bson_find_from_buffer(&it, args, "3");
    char* dst_epid = (char*)bson_iterator_string(&it);

    // signal destination opts
    bson_find_from_buffer(&it, args, "4");
    char* dst_opts = (char*)bson_iterator_value(&it);
    
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, dst_epid, &ep)) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping: Could not find endpoint %s, aborting!", dst_epid);
        rpc_server_error_msg(req, 61, "Invalid endpoint.");
        return;
    }
    if ( !ep->writable ) {
        WISHDEBUG(LOG_CRITICAL, "control.requestMapping: Endpoint %s not writable, aborting!", dst_epid);
        rpc_server_error_msg(req, 62, "Destination endpoint not writable.");
        return;
    }

    //bson_visit("control.requestMapping arguments:", args);
    
    int map_buf_len = 300;
    char map_buf[map_buf_len];

    /*
    self.ucp.request(peer, 'control.map', [fromEpid, fromOpts, toEpid], function(err, key) {
        if (err) { return res.error(key); }
        //console.log("control map response(err,data):", err, key);

        var settings = {
            epid: fromEpid,
            url: url,
            opts: toOpts };

        // key, toEpid, toOpts
        self.map(key, toEpid, settings, { peer: context.peer }, function (err, data) {
            res.send(data);
        });
    });
    */
    
    // send control.map request to the map signal source node
    bson map;
    bson_init_buffer(&map, map_buf, map_buf_len);
    bson_append_string(&map, "op", "control.map");
    bson_append_start_array(&map, "args");
    bson_append_string(&map, "0", src_epid);
    bson_append_element(&map, "1", &src_opts);
    bson_append_string(&map, "2", dst_epid);
    bson_append_finish_array(&map);
    bson_append_int(&map, "id", 0);
    bson_finish(&map);
    
    rpc_client_req* creq = rpc_client_request(&mist_app->protocol.rpc_client, &map, handle_control_map_response, req);

    if (creq == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Could not make control.map request: rpc_client_request returned NULL!");
        return;
    }
     
    //wish_app_send_context(mist_app->app, &src_peer, bson_data(&map), bson_size(&map), wish_app_send_mist_request_mapping_cb, req);
    wish_app_send_context(mist_app->app, &src_peer, bson_data(&map), bson_size(&map), NULL, NULL);
    // response will be sent to this request from handle_control_map_response
}

void handle_control_notify(rpc_server_req *req, const uint8_t* args) {
    wish_protocol_peer_t* peer = req->ctx;
    mist_app_t *mist_app = req->context;
    mist_model *model = &(mist_app->model);
    
    //WISHDEBUG(LOG_CRITICAL, "control.notify from peer: %p, said:", req->ctx);
    //bson_visit("control.notify", args);

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* endpoint = (char*)bson_iterator_string(&it);
    
    mist_ep* ep;
    if (mist_find_endpoint_by_name(model, endpoint, &ep)) {
        rpc_server_error_msg(req, 105, "Endpoint not found.");
        return;
    }
    
    if ( !ep->writable ) {
        rpc_server_error_msg(req, 105, "Endpoint not writable or permission denied.");
        return;
    }

    // TODO check the mapping ID 
    /*
    bson_find_from_buffer(&it, args, "1");
    char *mapping_id = NULL;
    if (bson_iterator_type(&it) == BSON_STRING) {
        mapping_id = (char *) bson_iterator_string(&it);
        WISHDEBUG(LOG_CRITICAL, "Mapping id: %s", mapping_id);
    }
    */
    
    bson_find_from_buffer(&it, args, "2");
    
    char buf[MIST_RPC_REPLY_BUF_LEN];

    bson b;
    bson_init_buffer(&b, buf, MIST_RPC_REPLY_BUF_LEN);
    bson_append_element(&b, "data", &it);
    bson_finish(&b);
    
    ep->write(ep, peer, 0, &b);
    
    int rbuf_len = 100;
    char rbuf[rbuf_len];
    
    bson bs;
    bson_init_buffer(&bs, rbuf, rbuf_len);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
}

void handle_control_unmap(rpc_server_req *req, const uint8_t* args) {
    wish_protocol_peer_t* peer = (wish_protocol_peer_t *)req->ctx;
    mist_app_t *mist_app = req->context;
    
    bson_visit("in handle_control_unmap", args);
    
    bson_iterator it;
    
    /* mapping id (string) as the sole argument */
    bson_find_from_buffer(&it, args, "0");
    if ( bson_iterator_type(&it) != BSON_STRING ) { 
        rpc_server_error_msg(req, 9999990, "Malformed mapping id");
        return; 
    }
    const char* mapping_id = bson_iterator_string(&it);
    WISHDEBUG(LOG_CRITICAL, "mapping_id %s", mapping_id);
    if (mist_mapping_delete(mist_app, peer, (char*) mapping_id)) {
        const size_t buf_len = 100;
        char buf[buf_len];
        bson b;
        bson_init_buffer(&b, buf, buf_len);
        bson_append_bool(&b, "data", true);
        bson_finish(&b);
        rpc_server_send(req, bson_data(&b), bson_size(&b));
    }
    else {
        rpc_server_error_msg(req, 999991, "Could not delete");
    }
}

/** De-allocator function for mist-app's control.signal rpc handler, for free'ing the peer whose copy was made because we needed to respons asynchronously. */
static void end_control_signals(rpc_server_req *req) {
    if (req->ctx) {
        wish_platform_free(req->ctx);
    }
}

void handle_control_signals(rpc_server_req *req, const uint8_t* args) {
    // It is necessary to make a copy of the peer, as the peer structure in req->ctx is stack-allocated
    wish_protocol_peer_t* peer = wish_platform_malloc(sizeof(wish_protocol_peer_t));
    memcpy(peer, req->ctx, sizeof(wish_protocol_peer_t));
    req->ctx = peer;
    req->end = end_control_signals;
    
    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "ok");
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
}