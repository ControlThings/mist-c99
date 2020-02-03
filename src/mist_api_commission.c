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
#include "mist_api_commission.h"

#include "stddef.h"
#include "stdbool.h"
#include "string.h"

#include "sandbox.h"
#include "utlist.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_debug.h"
#include "mist_api.h"
#include "mist_api_sandbox.h"
#include "mist_port.h"

static void commission_retry_action(mist_api_t* mist_api);

static int commission_state_timeout(enum commissioning_states state);

static int commission_state_retry_timeout(enum commissioning_states state);

#ifndef MIST_API_COMMISSION_TIME_SCALE
/** 
 * MIST_API_COMMISSION_TIME_SCALE indicates how many times per second commissioning_periodic is called.
 * 
 * This defines the scale factor for timeouts, which are internally expressed in seconds. 
 * If your port implementation calls Mist Api's wish app periodic with something else than 1-second intervals, then override this by re-declaring MIST_API_COMMISSION_TIME_SCALE in your implementation.
 * For example, mist node.js port (mist-node-api-node) must declare this to 50.
 */
#define MIST_API_COMMISSION_TIME_SCALE 1
#else
#pragma message "MIST_API_COMMISSION_TIME_SCALE re-defined"
#endif

/*
 * Create a reset event which cleans up wld_class etc. which may be alloc'ed.
 * 
 * Check to find WLD_CLASS_LEN
 * 
 * emit list of wifi networks seen by the commission target wifi:
 *     rpc_server_emit_broadcast(mist_api->server, "sandbox.commission.perform", )
 */

// TODO: Ensure this is right
#define TMP_WLD_CLASS_LEN 64


// log transitions / events

void commission_init(commissioning* c11g) {
    c11g->state = COMMISSION_STATE_INITIAL;
    c11g->wld_class = NULL;
    c11g->standalone_ssid = NULL;
    c11g->standalone_password = NULL;
}

static void commission_emit_string(mist_api_t* mist_api, const char* msg) {
    commissioning* c11g = &mist_api->commissioning;

    // emit progress
    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", msg);
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void commission_emit_event(mist_api_t* mist_api, const char* msg) {
    commissioning* c11g = &mist_api->commissioning;

    // emit progress
    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "event");
    bson_append_string(&bs, "1", msg);
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void commission_emit_state(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    // emit progress
    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "state");
    bson_append_string(&bs, "1", commission_state_to_string(c11g->state));
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);    
}

static void commission_cleanup(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;
    
    if (c11g->standalone_ssid) {
        wish_platform_free(c11g->standalone_ssid);
        c11g->standalone_ssid = NULL;
    }
    if (c11g->standalone_password) {
        wish_platform_free(c11g->standalone_password);
        c11g->standalone_password = NULL;
    }
    if (c11g->via_sandbox && c11g->sandbox_id) {
        wish_platform_free(c11g->sandbox_id);
        c11g->sandbox_id = NULL;
        c11g->via_sandbox = false;
    }
}

static void commission_transition(mist_api_t* mist_api, enum commissioning_states state) {
    commissioning* c11g = &mist_api->commissioning;
    c11g->state = state;
    c11g->timer = 0;
    c11g->retry_timer = 0;
    commission_emit_state(mist_api);
    
    if (state == COMMISSION_STATE_FINISHED_FAIL) {
        rpc_server_req* req = rpc_server_req_by_sid(mist_api->server, c11g->req_sid);

        if (req) {
            bson bs;
            bson_init(&bs);
            bson_append_start_object(&bs, "data");
            bson_append_finish_object(&bs);
            bson_finish(&bs);

            rpc_server_send(req, bson_data(&bs), bson_size(&bs));

            bson_destroy(&bs);
        }
        
        mist_port_wifi_join(mist_api, c11g->original_ssid, NULL);
        commission_cleanup(mist_api);
    } else if (state == COMMISSION_STATE_FINISHED_OK) {
        commission_cleanup(mist_api);
    }
}

void commission_periodic(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;
    
    if (c11g->state == COMMISSION_STATE_INITIAL) { return; }

    int retry_timeout = commission_state_retry_timeout(c11g->state);

    int timeout = commission_state_timeout(c11g->state);

    WISHDEBUG(LOG_CRITICAL, "commission_periodic %s %i (%i) retry %i", commission_state_to_string(c11g->state), c11g->timer, timeout, retry_timeout);

    if (retry_timeout != -1 && c11g->retry_timer >= ( retry_timeout * MIST_API_COMMISSION_TIME_SCALE ) ) {
         WISHDEBUG(LOG_CRITICAL, "commission retry action in %s", commission_state_to_string(c11g->state));
        commission_retry_action(mist_api);
        c11g->retry_timer = 0;
    }
    
    if (timeout != -1 && c11g->timer >= (timeout * MIST_API_COMMISSION_TIME_SCALE) ) {
        // timed out
        WISHDEBUG(LOG_CRITICAL, "Timed out in %s", commission_state_to_string(c11g->state));
        
        rpc_server_req* req = rpc_server_req_by_sid(mist_api->server, c11g->req_sid);
        
        if (req) {
            rpc_server_error_msg(req, 668, "Timeout.");
        }
        
        commission_transition(mist_api, COMMISSION_STATE_FINISHED_FAIL);
    }
    
    c11g->timer++;
    c11g->retry_timer++;
}

void mist_port_wifi_list_cb(mist_api_t* mist_api, bson* wifi_list) {
    WISHDEBUG(LOG_CRITICAL, "mist_port_wifi_list_cb");
}

/* Commission events */

void commission_event_start_wifi(mist_api_t* mist_api, const char* luid, 
        const char* ssid, const char* password, const char* wld_class) 
{
    commissioning* c11g = &mist_api->commissioning;

    WISHDEBUG(LOG_CRITICAL, "Start wifi commissioning, expected class %s", wld_class);
    commission_emit_event(mist_api, "start_wifi");
    
    c11g->is_wifi_commissioning = true;
    
    memcpy(c11g->peer.luid, luid, WISH_UID_LEN);
    if (wld_class != NULL) {
        c11g->wld_class = strdup(wld_class);
    }
    
    commission_transition(mist_api, COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI);
    mist_port_wifi_join(mist_api, ssid, password);
}

void commission_event_start_wld(mist_api_t* mist_api, const char* luid, 
        const char* ruid, const char* rhid, const char* wld_class)
{
    commissioning* c11g = &mist_api->commissioning;

    WISHDEBUG(LOG_CRITICAL, "Start wld commissioning, expected class %s", wld_class);
    commission_emit_event(mist_api, "start_wld");
    
    c11g->is_wifi_commissioning = false;
    c11g->original_ssid = NULL;

    if (wld_class != NULL) {
        c11g->wld_class = strdup(wld_class);
    }    

    // We have selected an item to commission, store info to context
    memcpy(c11g->peer.luid, luid, WISH_UID_LEN);
    memcpy(c11g->peer.ruid, ruid, WISH_UID_LEN);
    memcpy(c11g->peer.rhid, rhid, WISH_UID_LEN);
    memset(c11g->peer.rsid, 0, WISH_UID_LEN);
    strncpy(c11g->peer.protocol, "ucp", 4);
    
    commission_transition(mist_api, COMMISSION_STATE_WAIT_WLD_LIST);
    
    commission_event_wld_candidate_found(mist_api);
}

void commission_event_wld_clear_cb(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "wld_clear_cb");
    
    if (c11g->state == COMMISSION_STATE_WAIT_WLD_CLEAR) {
        // legal 

        WISHDEBUG(LOG_CRITICAL, "commission_event_wld_clear_cb");
        
        commission_transition(mist_api, COMMISSION_STATE_WAIT_WLD_LIST);
    }
}

static void wld_clear_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    // FIXME: The passthru_ctx2 is should be translated back to req->cb_context or ctx, but is not!
    // This problem is due to incomplete implementation in wish_rpc (related to wish_api_request_context())
    mist_api_t* mist_api = req->passthru_ctx2;
    
    WISHDEBUG(LOG_CRITICAL, "wld_clear_cb %i", mist_api->commissioning.state);
    
    commission_event_wld_clear_cb(mist_api);
}

void commission_event_wifi_join_ok(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "wifi_join_ok");
    
    if (c11g->state == COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI) {
        // legal 
        
        // clear wld and wait for new items to appear by listening to event_wld_signal
        
        commission_transition(mist_api, COMMISSION_STATE_WAIT_WLD_CLEAR);

        WISHDEBUG(LOG_CRITICAL, "commission_event_wifi_join_ok");
        
        bson bs;
        bson_init(&bs);
        bson_append_string(&bs, "op", "wld.clear");
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", 0);
        bson_finish(&bs);
        
        WISHDEBUG(LOG_CRITICAL, "mist_api is: %p", mist_api);
        
        wish_api_request_context(mist_api, &bs, wld_clear_cb, mist_api);
                
        bson_destroy(&bs);
    } else {
        // illegal
    }
}

void commission_event_wifi_join_failed(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "wifi_join_failed");
    
    if (c11g->state == COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE) {
        // emit progress
        bson bs;
        bson_init(&bs);
        bson_append_string(&bs, "data", "COMMISSION_STATE_WIFI_JOIN_FAILED, but disregarding.");
        bson_finish(&bs);

        rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);        
        return;
    }
    
    commission_transition(mist_api, COMMISSION_STATE_FINISHED_FAIL);
}

static void wld_friend_request_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    // FIXME: The passthru_ctx2 is should be translated back to req->cb_context or ctx, but is not!
    // This problem is due to incomplete implementation in wish_rpc (related to wish_api_request_context())
    mist_api_t* mist_api = req->passthru_ctx2;
    commissioning* c11g = &mist_api->commissioning;
    
    if (c11g->state == COMMISSION_STATE_WAIT_FRIEND_REQ_RESP) {
        // legal
        
        bson_visit("got friend req resp:", payload);
        
        //commission_event_friend_req_resp
    }
}

static void commission_do_friend_request(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;
    bson bs;
    bson_init(&bs);
    bson_append_string(&bs, "op", "wld.friendRequest");
    bson_append_start_array(&bs, "args");
    bson_append_binary(&bs, "0", c11g->peer.luid, WISH_UID_LEN);
    bson_append_binary(&bs, "1", c11g->peer.ruid, WISH_UID_LEN);
    bson_append_binary(&bs, "2", c11g->peer.rhid, WISH_UID_LEN);
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", 0);
    bson_finish(&bs);

    wish_api_request_context(mist_api, &bs, wld_friend_request_cb, mist_api);

    bson_destroy(&bs);
}

void commission_event_wld_candidate_found(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "wld_candidate_found");
    
    if (c11g->state == COMMISSION_STATE_WAIT_WLD_LIST) {
        // legal 

        WISHDEBUG(LOG_CRITICAL, "commission_event_wld_candidate_found");
        commission_do_friend_request(mist_api);
        commission_transition(mist_api, COMMISSION_STATE_WAIT_FRIEND_REQ_RESP);
    }
}

void commission_event_wld_candidate_already_claimed(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "wld_candidate_already_claimed");
    
    if (c11g->state == COMMISSION_STATE_WAIT_WLD_LIST) {
        // legal 

        WISHDEBUG(LOG_CRITICAL, "commission_event_wld_candidate_found");
        commission_transition(mist_api, COMMISSION_STATE_FINISHED_FAIL);
    }
}

static void wld_list_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    // FIXME: The passthru_ctx2 is should be translated back to req->cb_context or ctx, but is not!
    // This problem is due to incomplete implementation in wish_rpc (related to wish_api_request_context())
    mist_api_t* mist_api = req->passthru_ctx2;
    commissioning* c11g = &mist_api->commissioning;
    
    if (c11g->state == COMMISSION_STATE_WAIT_WLD_LIST) {
        // legal
        //WISHDEBUG(LOG_CRITICAL, "wld_list_cb");

        /*
        if (!Arrays.equals(arrayList.get(i).getRhid(), localCoreHostId) && currentState == State.WAIT_WLD_LIST) {
            friendCandidate = arrayList.get(i);
            reportEvent(Event.ON_WLD_LIST_OK);
            wldListTimer.cancel();
            wldListTimer = null;
        }
        */
        
        //bson_visit("wld_list_cb bson:", payload);
        
        bson_iterator it;
        bson_iterator sit;
        bson_iterator_from_buffer(&it, payload);
        bson_find_fieldpath_value("data.0", &it);
        
        do {
            bson_iterator_subiterator(&it, &sit);

            if ( BSON_BINDATA == bson_find_fieldpath_value("rhid", &sit) ) {
                // skip myself
                if (memcmp(mist_api->wish_app->whid, bson_iterator_bin_data(&sit), WISH_WHID_LEN) == 0) {
                    continue;
                }
            }
            
            bson_iterator_subiterator(&it, &sit);
            
            if ( BSON_STRING == bson_find_fieldpath_value("alias", &sit) ) {
                WISHDEBUG(LOG_CRITICAL, "alias: %s, expected commissioning class %s", bson_iterator_string(&sit), c11g->wld_class);
            }
            
            
            if (c11g->wld_class != NULL) {
                bson_iterator_subiterator(&it, &sit);

                if ( BSON_STRING != bson_find_fieldpath_value("class", &sit) ) {
                    continue;
                }
                
                if (strncmp(c11g->wld_class, bson_iterator_string(&sit), TMP_WLD_CLASS_LEN) != 0 ) {
                    continue;
                }
                
                // if we come this far the class is correct, falling through
            }
            
            // check claimable key exists and is true (claim: true)
            bson_iterator_subiterator(&it, &sit);
            
            if ( BSON_BOOL != bson_find_fieldpath_value("claim", &sit) ) {
                commission_event_wld_candidate_already_claimed(mist_api);
                continue;
            }
            
            if (!bson_iterator_bool(&sit)) {
                commission_event_wld_candidate_already_claimed(mist_api);
                continue;
            }
            
            const char* ruid = NULL;
            const char* rhid = NULL;

            bson_iterator_subiterator(&it, &sit);
            
            if ( BSON_BINDATA == bson_find_fieldpath_value("ruid", &sit) ) {
                ruid = bson_iterator_bin_data(&sit);
            }

            bson_iterator_subiterator(&it, &sit);
            
            if ( BSON_BINDATA == bson_find_fieldpath_value("rhid", &sit) ) {
                rhid = bson_iterator_bin_data(&sit);
            }
            
            // We have selected an item to commission, store info to context
            memcpy(c11g->peer.ruid, ruid, WISH_UID_LEN);
            memcpy(c11g->peer.rhid, rhid, WISH_UID_LEN);
            strncpy(c11g->peer.protocol, "ucp", 4);
            
            
            // send friend request and wait for response

            
            
            commission_event_wld_candidate_found(mist_api);
            
            
            break;
        } while (BSON_OBJECT == bson_iterator_next(&it));
    }
}

void commission_event_wld_signal(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    WISHDEBUG(LOG_CRITICAL, "commission_event_wld_signal %i", c11g->state);
    
    commission_emit_event(mist_api, "wld_signal");
    
    if (c11g->state == COMMISSION_STATE_WAIT_WLD_LIST) {
        // legal 
        
        
        bson bs;
        bson_init(&bs);
        bson_append_string(&bs, "op", "wld.list");
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", 0);
        bson_finish(&bs);
        
        wish_api_request_context(mist_api, &bs, wld_list_cb, mist_api);
                
        bson_destroy(&bs);        
        
        
    } else {
        // illegal
    }
        
}

static void check_connections_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    // FIXME: The passthru_ctx2 is should be translated back to req->cb_context or ctx, but is not!
    // This problem is due to incomplete implementation in wish_rpc (related to wish_api_request_context())
    //mist_api_t* mist_api = req->passthru_ctx2;
    //commissioning* c11g = &mist_api->commissioning;

    /* Note: This callback is also used when performing a checkConnections as "retry timeout" action for state COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE */
}

void commission_event_friend_req_accepted_signal(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "friend_req_accepted");

    WISHDEBUG(LOG_CRITICAL, "commission_event_friend_req_accepted_signal %i", c11g->state);
    
    if (c11g->state == COMMISSION_STATE_WAIT_FRIEND_REQ_RESP) {
        // legal 

        if (mist_api->commissioning.via_sandbox) {
            sandbox_t* sandbox = mist_sandbox_by_id(mist_api, mist_api->commissioning.sandbox_id);

            if (sandbox == NULL) {
                //rpc_server_error_msg(req, 58, "Sandbox not found.");
                WISHDEBUG(LOG_CRITICAL, "Sandbox not found.");
                return;
            }


            // clean up peers from sandbox which are from the same host
            sandbox_peers_t* peers;
            sandbox_peers_t* tmp;

            wish_protocol_peer_t* peer = NULL;

            LL_FOREACH_SAFE(sandbox->peers, peers, tmp) {
                if ( memcmp(peers->peer.luid, c11g->peer.luid, 32) == 0 &&
                     memcmp(peers->peer.ruid, c11g->peer.ruid, 32) == 0 &&
                     memcmp(peers->peer.rhid, c11g->peer.rhid, 32) == 0 &&
                     //memcmp(peers->peer.rsid, c11g->peer->rsid, 32) == 0 &&
                     strncmp(peers->peer.protocol, c11g->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
                {
                    LL_DELETE(sandbox->peers, peers);
                    WISHDEBUG(LOG_CRITICAL, "Deleted peer from sandbox");
                }
            }
        }
        
        commission_transition(mist_api, COMMISSION_STATE_WAIT_FOR_PEERS);

        // signal peers, in the case we were already friends and the peers are actually already online
        commission_event_peers_signal(mist_api);
        

        /*
         * This currently only tries to connect via relay, but could be fixed 
         * to use local discovery db to connect locally if possible.
         * 
        // send checkConnections to possibly speed up getting the peers
        bson bs;
        bson_init(&bs);
        bson_append_string(&bs, "op", "connections.checkConnections");
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", 0);
        bson_finish(&bs);
        
        wish_api_request(mist_api, &bs, check_connections_cb);
        */
    }    
}

void commission_event_friend_req_declined_signal(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "friend_req_declined");
    
    WISHDEBUG(LOG_CRITICAL, "commission_event_friend_req_declined_signal %i, finishing with fail", c11g->state);
    
     if (c11g->state == COMMISSION_STATE_WAIT_FRIEND_REQ_RESP) {
         commission_transition(mist_api, COMMISSION_STATE_FINISHED_FAIL);
     }
}

static void wifi_list_available_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = req->cb_context;
    commissioning* c11g = &mist_api->commissioning;

    if (c11g->state == COMMISSION_STATE_WAIT_WIFI_CONFIG) {
        // legal
    
        bson_visit("wifis in device", payload);

        bson_iterator it;
        if (BSON_EOO == bson_find_from_buffer(&it, payload, "data") ) {
            // bail out
            // TODO: Fix error reporting
            commission_transition(mist_api, COMMISSION_STATE_FINISHED_FAIL);
            return;
        }
        
        // emit progress
        bson bs;
        bson_init(&bs);
        bson_append_start_array(&bs, "data");
        bson_append_string(&bs, "0", "wifiListAvailable");
        bson_append_element(&bs, "1", &it);
        bson_append_finish_array(&bs);
        bson_finish(&bs);

        rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);
    }    
}
static void claim_core_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = req->cb_context;
    commissioning* c11g = &mist_api->commissioning;
    
    if (c11g->state == COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB) {
        // legal
        
        bson_visit("claim_core_cb", payload);

        bson_iterator it;
        if (BSON_ARRAY == bson_find_from_buffer(&it, payload, "data") ) {
            // it is expected that claim_core_cb receives and object
            // { data: [{ rsid: Buffer, name: string }, ...] }

            WISHDEBUG(LOG_CRITICAL, "serviceList is array (data element ok)");
            
            // emit progress
            bson bs;
            bson_init(&bs);
            bson_append_start_array(&bs, "data");
            bson_append_string(&bs, "0", "claimedServices");
            bson_append_element(&bs, "1", &it);
            bson_append_finish_array(&bs);
            bson_finish(&bs);

            rpc_server_emit_broadcast(mist_api->server, mist_api->commissioning.via_sandbox ? "sandboxed.commission.perform" : "commission.perform", bson_data(&bs), bson_size(&bs));
            bson_destroy(&bs);
        } else {
            WISHDEBUG(LOG_CRITICAL, "serviceList not array (data element)");
        }
        
        // if wifi then list wifis else we're done
        if(c11g->is_wifi_commissioning) {
            commission_transition(mist_api, COMMISSION_STATE_WAIT_WIFI_CONFIG);
            
            // invoke claim endpoint
            
            bson req;
            bson_init(&req);
            bson_append_string(&req, "op", "control.invoke");
            bson_append_start_array(&req, "args");
            bson_append_string(&req, "0", "mist.wifiListAvailable");
            bson_append_finish_array(&req);
            bson_append_int(&req, "id", 0);
            bson_finish(&req);
            
            rpc_client_req* creq = mist_app_request(mist_api->mist_app, &c11g->peer, &req, wifi_list_available_cb);
            creq->cb_context = mist_api;
            
            bson_destroy(&req);
        
        } else {
            // we are done
            commission_transition(mist_api, COMMISSION_STATE_FINISHED_OK);
            // TODO: Fix termination of commissioning
            rpc_server_req* req = rpc_server_req_by_sid(mist_api->server, c11g->req_sid);

            if (req) {
                bson bs;
                bson_init(&bs);
                bson_append_start_object(&bs, "data");
                bson_append_finish_object(&bs);
                bson_finish(&bs);
                
                rpc_server_send(req, bson_data(&bs), bson_size(&bs));
                
                bson_destroy(&bs);
            }
            commission_transition(mist_api, COMMISSION_STATE_INITIAL);
            
        }
    }    
}

static void commission_invoke_claim_core(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;
    // invoke claim endpoint

    bson req;
    bson_init(&req);
    bson_append_string(&req, "op", "control.invoke");
    bson_append_start_array(&req, "args");
    bson_append_string(&req, "0", "claimCore");
    bson_append_finish_array(&req);
    bson_append_int(&req, "id", 0);
    bson_finish(&req);

    rpc_client_req* creq = mist_app_request(mist_api->mist_app, &c11g->peer, &req, claim_core_cb);
    creq->cb_context = mist_api;

    bson_destroy(&req);
}

static void read_mist_name_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = req->cb_context;
    commissioning* c11g = &mist_api->commissioning;
    wish_protocol_peer_t* peer = req->passthru_ctx;
    
    //WISHDEBUG(LOG_CRITICAL, "mist_name mist_api / app %p %p %p", ctx, , req->client->context);

    bson_iterator it;
    bson_iterator_from_buffer(&it, payload);

    if ( BSON_STRING == bson_find_fieldpath_value("data", &it) ) {
        WISHDEBUG(LOG_CRITICAL, "mist_name_cb: %s (%s)", bson_iterator_string(&it), commission_state_to_string(c11g->state));
    }
    
    if (c11g->state == COMMISSION_STATE_WAIT_FOR_PEERS) {
        // legal
        
        // check key data == "MistConfig"
        bson_iterator_from_buffer(&it, payload);
        
        if ( BSON_STRING != bson_find_fieldpath_value("data", &it) ) {
            // failed, ignore
            goto cleanup;
        }
        
        if ( strncmp("MistConfig", bson_iterator_string(&it), 11) == 0 ) {
            // found it!
            
            // store the peer
            memcpy(&c11g->peer, peer, sizeof(wish_protocol_peer_t));
            
            commission_transition(mist_api, COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB);
            
            commission_invoke_claim_core(mist_api);
        }
        
        //bson_visit("read_mist_name_cb:", payload);
        
        //commission_event_friend_req_resp
cleanup:
        // clean up the peer
        wish_platform_free(peer);
    }
}

void commission_event_peers_signal(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "peers_signal");
    
    WISHDEBUG(LOG_CRITICAL, "commission_event_peers_signal %i", c11g->state);
    
    WISHDEBUG(LOG_CRITICAL, "mist_api /app real %p %p", mist_api, mist_api->mist_app);
    
    if (c11g->state == COMMISSION_STATE_WAIT_FOR_PEERS) {
        // legal 

        WISHDEBUG(LOG_CRITICAL, "Peers signal");
        
        //commission_transition(mist_api, COMMISSION_STATE_WAIT_FOR_PEERS);

        peers_list* peers;
        
        wish_protocol_peer_t* peer = NULL;
        
        LL_FOREACH(mist_api->peers_db, peers) {
            if ( memcmp(peers->peer.luid, c11g->peer.luid, 32) == 0 &&
                 memcmp(peers->peer.ruid, c11g->peer.ruid, 32) == 0 &&
                 memcmp(peers->peer.rhid, c11g->peer.rhid, 32) == 0 &&
                 //memcmp(peers->peer.rsid, c11g->peer->rsid, 32) == 0 &&
                 strncmp(peers->peer.protocol, c11g->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                peer = &peers->peer;
                WISHDEBUG(LOG_CRITICAL, "Found peer, rsid %02x %02x %02x %s", peer->rsid[0], peer->rsid[1], peer->rsid[2], peer->online ? "online" : "offline");
                
                if (peer) {
                    // mist.request('mist.control.read', [peer, 'mist.name'], () => {
                    //     check that it is MistConfig
                    // })

                    if (mist_api->commissioning.via_sandbox) {
                        sandbox_t* sandbox = mist_sandbox_by_id(mist_api, mist_api->commissioning.sandbox_id);

                        if (sandbox == NULL) {
                            //rpc_server_error_msg(req, 58, "Sandbox not found.");
                            WISHDEBUG(LOG_CRITICAL, "Sandbox not found.");
                            return;
                        }

                        bool added = sandbox_add_peer(sandbox, peer);

                        if (added) {
                            sandbox_save(mist_api);
                        }
                    }
                    
                    //if (added) {
                        bson req;
                        bson_init(&req);
                        bson_append_string(&req, "op", "control.read");
                        bson_append_start_array(&req, "args");
                        bson_append_string(&req, "0", "mist.name");
                        bson_append_finish_array(&req);
                        bson_append_int(&req, "id", 0);
                        bson_finish(&req);

                        wish_protocol_peer_t* candidate_peer = wish_platform_malloc(sizeof(wish_protocol_peer_t));
                        memcpy(candidate_peer, peer, sizeof(wish_protocol_peer_t));

                        rpc_client_req* creq = mist_app_request(mist_api->mist_app, candidate_peer, &req, read_mist_name_cb);
                        creq->cb_context = mist_api;
                        creq->passthru_ctx = candidate_peer;

                        bson_destroy(&req);
                        WISHDEBUG(LOG_CRITICAL, "control.read sent to peer. %i", creq->id);

                    //} else {
                    //    WISHDEBUG(LOG_CRITICAL, "Peer already added.");
                    //}
                }
            }
        }
    } else if (c11g->state == COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE) {
        WISHDEBUG(LOG_CRITICAL, "Peers signal while waiting for commissioned peer offline");

        
        // now move back to original wifi, and wait for peers to emerge (or fail waiting)
        // this action is delayed due to some platforms being so quick to disconnect
        // that the selectWifi message is never sent.
        mist_port_wifi_join(mist_api, c11g->original_ssid, NULL);
        
        
        peers_list* peers;
        
        wish_protocol_peer_t* peer = NULL;
        
        LL_FOREACH(mist_api->peers_db, peers) {
            if ( memcmp(peers->peer.luid, c11g->peer.luid, 32) == 0 &&
                 memcmp(peers->peer.ruid, c11g->peer.ruid, 32) == 0 &&
                 memcmp(peers->peer.rhid, c11g->peer.rhid, 32) == 0 &&
                 memcmp(peers->peer.rsid, c11g->peer.rsid, 32) == 0 &&
                 !peers->peer.online &&
                 strncmp(peers->peer.protocol, c11g->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                peer = &peers->peer;
                break;
            }
        }

        if (peer) {
            // we are all done
            commission_transition(mist_api, COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE);
        }
    } else if (c11g->state == COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE) {
        WISHDEBUG(LOG_CRITICAL, "Peers signal while waiting for commissioned peer online");
        
        peers_list* peers;
        
        wish_protocol_peer_t* peer = NULL;
        
        LL_FOREACH(mist_api->peers_db, peers) {
            if ( memcmp(peers->peer.luid, c11g->peer.luid, 32) == 0 &&
                 memcmp(peers->peer.ruid, c11g->peer.ruid, 32) == 0 &&
                 memcmp(peers->peer.rhid, c11g->peer.rhid, 32) == 0 &&
                 memcmp(peers->peer.rsid, c11g->peer.rsid, 32) == 0 &&
                 peers->peer.online &&
                 strncmp(peers->peer.protocol, c11g->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN) == 0 )
            {
                peer = &peers->peer;
                break;
            }
        }

        if (peer) {
            // we are all done
            commission_transition(mist_api, COMMISSION_STATE_FINISHED_OK);
            
            // clean up request as we are done.
            rpc_server_req* req = rpc_server_req_by_sid(mist_api->server, c11g->req_sid);

            if (req) {
                bson bs;
                bson_init(&bs);
                bson_append_start_object(&bs, "data");
                bson_append_finish_object(&bs);
                bson_finish(&bs);
                
                rpc_server_send(req, bson_data(&bs), bson_size(&bs));
                
                bson_destroy(&bs);
            }
            commission_transition(mist_api, COMMISSION_STATE_INITIAL);
        }
    }
}

static void select_wifi_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    // we will never get here, because the device will move to the wifi given
    
    mist_api_t* mist_api = req->cb_context;
    //commissioning* c11g = &mist_api->commissioning;
    
    bson_visit("select_wifi_cb", payload);
    
    //commission_event_select_wifi_cb(mist_api);
}
static void disconnect_all_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    //mist_api_t* mist_api = req->cb_context;
    //commissioning* c11g = &mist_api->commissioning;
    
    bson_visit("disconnectAll cb:", payload);
}
    
void commission_event_select_wifi(mist_api_t* mist_api, const char* type, const char* ssid, const char* password) {
    commissioning* c11g = &mist_api->commissioning;

    commission_emit_event(mist_api, "select_wifi");

    
    WISHDEBUG(LOG_CRITICAL, "commission_event_select_wifi: %s", commission_state_to_string(c11g->state));
    
    if (c11g->state == COMMISSION_STATE_WAIT_WIFI_CONFIG) {
        // legal
        
        // TODO: transition to new path if access-point mode (not station)
        if (strncmp(type, "access-point", 13) == 0) {
            commission_transition(mist_api, COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE);
        } else {
            commission_transition(mist_api, COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE);
        }

        // invoke mistWifiCommissioning endpoint
        bson req;
        bson_init(&req);
        bson_append_string(&req, "op", "control.invoke");
        bson_append_start_array(&req, "args");
        bson_append_string(&req, "0", "mist.wifiCommissioning");
        bson_append_start_object(&req, "1");
        bson_append_string(&req, "type", type);
        bson_append_string(&req, "ssid", ssid);
        if (password) {
            bson_append_string(&req, "password", password);
        }
        bson_append_finish_array(&req);
        bson_append_finish_array(&req);
        bson_append_int(&req, "id", 0);
        bson_finish(&req);

        rpc_client_req* creq = mist_app_request(mist_api->mist_app, &c11g->peer, &req, select_wifi_cb);
        creq->cb_context = mist_api;

        bson_destroy(&req);
        
        if (strncmp(type, "access-point", 13) == 0) {
            mist_port_wifi_join(mist_api, ssid, password);
            if (ssid != NULL) {
                c11g->standalone_ssid = strdup(ssid);
            }
            if (password != NULL) {
                c11g->standalone_password = strdup(password);
            }
        }

        bson bs;
        bson_init(&bs);
        bson_append_string(&bs, "op", "connections.disconnectAll");
        bson_append_start_array(&bs, "args");
        bson_append_finish_array(&bs);
        bson_append_int(&bs, "id", 0);
        bson_finish(&bs);

        wish_api_request_context(mist_api, &bs, disconnect_all_cb, mist_api);

        bson_destroy(&bs);        
    }
}

void mist_port_wifi_join_cb(mist_api_t* mist_api, wifi_join result) {
    switch (result) {
        case WIFI_JOIN_OK:
            commission_event_wifi_join_ok(mist_api);
            break;
        case WIFI_OFF:
            commission_transition(mist_api, COMMISSION_STATE_WIFI_DISABLED);
            commission_event_wifi_join_failed(mist_api);
            break;
        case WIFI_JOIN_FAILED:
        default:
            commission_event_wifi_join_failed(mist_api);
            break;
    }
}


const char* commission_state_to_string(enum commissioning_states state) {
    switch(state) {
        case COMMISSION_STATE_INITIAL:
            return "COMMISSION_STATE_INITIAL";
            break;
        case COMMISSION_STATE_NO_CALLBACK_LISTENER:
            return "COMMISSION_STATE_NO_CALLBACK_LISTENER";
            break;
        case COMMISSION_STATE_WAIT_WLD_OR_WIFI_SELECT:
            return "COMMISSION_STATE_WAIT_WLD_OR_WIFI_SELECT";
            break;
        case COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI:
            return "COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI";
            break;
        case COMMISSION_STATE_WAIT_WIFI_ENABLED:
            return "COMMISSION_STATE_WAIT_WIFI_ENABLED";
            break;
        case COMMISSION_STATE_WIFI_DISABLED:
            return "COMMISSION_STATE_WIFI_DISABLED";
            break;
        case COMMISSION_STATE_WAIT_WLD_CLEAR:
            return "COMMISSION_STATE_WAIT_WLD_CLEAR";
            break;
        case COMMISSION_STATE_WAIT_WLD_LIST:
            return "COMMISSION_STATE_WAIT_WLD_LIST";
            break;
        case COMMISSION_STATE_WAIT_SELECT_LOCAL_ID:
            return "COMMISSION_STATE_WAIT_SELECT_LOCAL_ID";
            break;
        case COMMISSION_STATE_WAIT_FRIEND_REQ_RESP:
            return "COMMISSION_STATE_WAIT_FRIEND_REQ_RESP";
            break;
        case COMMISSION_STATE_WAIT_FOR_PEERS:
            return "COMMISSION_STATE_WAIT_FOR_PEERS";
            break;
        case COMMISSION_STATE_WAIT_FOR_CLAIM_USER_DECISION:
            return "COMMISSION_STATE_WAIT_FOR_CLAIM_USER_DECISION";
            break;
        case COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB:
            return "COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB";
            break;
        case COMMISSION_STATE_WAIT_WIFI_CONFIG:
            return "COMMISSION_STATE_WAIT_WIFI_CONFIG";
            break;
        case COMMISSION_STATE_WAIT_JOIN_ORIGINAL_WIFI:
            return "COMMISSION_STATE_WAIT_JOIN_ORIGINAL_WIFI";
            break;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE:
            return "COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE";
            break;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE:
            return "COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE";
            break;
        case COMMISSION_STATE_FINISHED_OK:
            return "COMMISSION_STATE_FINISHED_OK";
            break;
        case COMMISSION_STATE_FINISHED_FAIL:
            return "COMMISSION_STATE_FINISHED_FAIL";
            break;
        case COMMISSION_STATE_ABORTED:
            return "COMMISSION_STATE_ABORTED";
            break;
    };
    
    return "Unknown commission state.";
}

/**
    @return the state's timeout in seconds or -1 if no timeout defined
*/
static int commission_state_timeout(enum commissioning_states state) {
    switch(state) {
        case COMMISSION_STATE_INITIAL:                        return -1;
        case COMMISSION_STATE_NO_CALLBACK_LISTENER:           return -1;
        case COMMISSION_STATE_WAIT_WLD_OR_WIFI_SELECT:        return -1;
        case COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI:    return 60;
        case COMMISSION_STATE_WAIT_WIFI_ENABLED:              return -1;
        case COMMISSION_STATE_WIFI_DISABLED:                  return -1;
        case COMMISSION_STATE_WAIT_WLD_CLEAR:                 return 5;
        case COMMISSION_STATE_WAIT_WLD_LIST:                  return 30;
        case COMMISSION_STATE_WAIT_SELECT_LOCAL_ID:           return -1;
        case COMMISSION_STATE_WAIT_FRIEND_REQ_RESP:           return 70;
        case COMMISSION_STATE_WAIT_FOR_PEERS:                 return 70;
        case COMMISSION_STATE_WAIT_FOR_CLAIM_USER_DECISION:   return -1;
        case COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB:           return 30;
        case COMMISSION_STATE_WAIT_WIFI_CONFIG:               return -1;
        case COMMISSION_STATE_WAIT_JOIN_ORIGINAL_WIFI:        return 60;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE: return 20;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE:  return 40;
        case COMMISSION_STATE_FINISHED_OK:                    return -1;
        case COMMISSION_STATE_FINISHED_FAIL:                  return -1;
        case COMMISSION_STATE_ABORTED:                        return -1;
    };
    
    return -1;
}

/**
    @return the state's retry timeout in seconds, or -1 if no retry timeout defined
*/
static int commission_state_retry_timeout(enum commissioning_states state) {
    switch(state) {
        case COMMISSION_STATE_INITIAL:                        return -1;
        case COMMISSION_STATE_NO_CALLBACK_LISTENER:           return -1;
        case COMMISSION_STATE_WAIT_WLD_OR_WIFI_SELECT:        return -1;
        case COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI:    return -1;
        case COMMISSION_STATE_WAIT_WIFI_ENABLED:              return -1;
        case COMMISSION_STATE_WIFI_DISABLED:                  return -1;
        case COMMISSION_STATE_WAIT_WLD_CLEAR:                 return -1;
        case COMMISSION_STATE_WAIT_WLD_LIST:                  return -1;
        case COMMISSION_STATE_WAIT_SELECT_LOCAL_ID:           return -1;
        case COMMISSION_STATE_WAIT_FRIEND_REQ_RESP:           return 5;
        case COMMISSION_STATE_WAIT_FOR_PEERS:                 return -1;
        case COMMISSION_STATE_WAIT_FOR_CLAIM_USER_DECISION:   return -1;
        case COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB:           return 5;
        case COMMISSION_STATE_WAIT_WIFI_CONFIG:               return -1;
        case COMMISSION_STATE_WAIT_JOIN_ORIGINAL_WIFI:        return -1;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE: return -1;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE:  return 15;
        case COMMISSION_STATE_FINISHED_OK:                    return -1;
        case COMMISSION_STATE_FINISHED_FAIL:                  return -1;
        case COMMISSION_STATE_ABORTED:                        return -1;
    };

    return -1;
}

static void commission_do_check_connections(mist_api_t *mist_api) {
    WISHDEBUG(LOG_CRITICAL, "Doing connections.checkConnections");

    bson bs;
    bson_init(&bs);
    bson_append_string(&bs, "op", "connections.checkConnections");
    bson_append_start_array(&bs, "args");
    bson_append_finish_array(&bs);
    bson_append_int(&bs, "id", 0);
    bson_finish(&bs);

    wish_api_request_context(mist_api, &bs, check_connections_cb, mist_api);

    bson_destroy(&bs);
}

static void commission_retry_action(mist_api_t* mist_api) {
    commissioning* c11g = &mist_api->commissioning;
    switch (c11g->state) {
        case COMMISSION_STATE_WAIT_FRIEND_REQ_RESP:
            commission_do_friend_request(mist_api);
            break;
        case COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB:
            commission_invoke_claim_core(mist_api);
            break;
        case COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE:
            commission_do_check_connections(mist_api);
            
            if (c11g->standalone_ssid) {
                // this is needed for standalone mode
                mist_port_wifi_join(mist_api, c11g->standalone_ssid, c11g->standalone_password);
            }
            break;
        default:
            WISHDEBUG(LOG_CRITICAL, "commission_retry_action called in state %s but no specific retry action is defined!", commission_state_to_string(c11g->state));
            break;
    }
}