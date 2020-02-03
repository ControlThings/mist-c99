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
#include "mist_api_sandbox.h"

#include "stddef.h"
#include "stdbool.h"
#include "string.h"

#include "sandbox.h"
#include "utlist.h"
#include "wish_fs.h"
#include "bson.h"
#include "bson_visit.h"
#include "wish_debug.h"
#include "mist_api_commission_handlers.h"

sandbox_t* mist_sandbox_by_id(mist_api_t* mist_api, const char* id) {
    sandbox_t* elt;
    
    if (id == NULL) { return NULL; }
    
    DL_FOREACH(mist_api->sandbox_db, elt) {
        //WISHDEBUG(LOG_CRITICAL, "  * a sandbox: %02x %02x %02x", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2]);
        if (memcmp(id, elt->sandbox_id, 32) == 0) {
            //WISHDEBUG(LOG_CRITICAL, "Found!: %02x %02x %02x", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2]);
            return elt;
        }
    }
    
    return NULL;
}

static bool mist_sandbox_uid_in_peers(mist_api_t* mist_api, sandbox_t* sandbox, const char* uid) {
    sandbox_peers_t* elt;
    
    DL_FOREACH(sandbox->peers, elt) {
        //WISHDEBUG(LOG_CRITICAL, "  * a sandbox: %02x %02x %02x %s", sandbox->sandbox_id[0], sandbox->sandbox_id[1], sandbox->sandbox_id[2], sandbox->name);
        if (memcmp(uid, elt->peer.luid, 32) == 0 || memcmp(uid, elt->peer.ruid, 32) == 0) {
            //WISHDEBUG(LOG_CRITICAL, "Found!: %02x %02x %02x", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2]);
            return true;
        }
    }
    
    return NULL;
}

/**
 * Remove all peers from all sandboxes with ruid equal to given uid
 * 
 * @param mist_api
 * @param uid
 */
void mist_sandbox_remove_peers_by_uid(mist_api_t* mist_api, const char* uid) {
    sandbox_t* sandbox;
    bool removed = false;

    LL_FOREACH(mist_api->sandbox_db, sandbox) {
        sandbox_peers_t* elt;
        sandbox_peers_t* tmp;
        LL_FOREACH_SAFE(sandbox->peers, elt, tmp) {
            if (memcmp(uid, elt->peer.ruid, 32) == 0) {
                LL_DELETE(sandbox->peers, elt);
                removed = true;
                wish_platform_free(elt);
            }
        }
    }
    
    if (removed) { sandbox_signals_emit(mist_api, "peers"); }
    
    sandbox_save(mist_api);
}

void sandbox_passthrough_end(rpc_server_req *req) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end, end... %p", req);
    
    rpc_client* peer_client = &mist_api->mist_app->protocol.rpc_client;
    rpc_client_req* e = rpc_client_find_passthru_req(peer_client, req->id);
    if (e==NULL) {
        WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end couldn't find request based on req->id: %i", req->id);
    } else {
        //WISHDEBUG(LOG_CRITICAL, "sandbox_passthrough_end north ID: %i south ID: %i (passthrough id: %i peer: %p)", req->id, e->id, e->passthru_id, e->passthru_ctx);
        
        // Update the send_ctx for each call to passthrough. This is required because 
        // there is not own clients for each remote peer as there "shuold" be.
        peer_client->send_ctx = e->passthru_ctx;
        
        rpc_client_end_by_id(peer_client, e->id);
    }
}

void sandbox_passthrough(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    // Make a generic function for passing the control.* and manage.* commands to the device.

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }
    
    bson_find_from_buffer(&it, args, "1");
    char* bson_peer = (char*)bson_iterator_value(&it);

    wish_protocol_peer_t pe;
    bool success = wish_protocol_peer_populate_from_bson(&pe, bson_peer);
    
    if (!success) {
        bson_visit("Failed getting peer from", bson_peer);
        rpc_server_error_msg(req, 55, "Peer not found.");
        return;
    }
    
    wish_protocol_peer_t* peer = mist_api_peer_find(mist_api, &pe);
    
    if (peer == NULL) {
        rpc_server_error_msg(req, 55, "Peer not found.");
        //WISHDEBUG(LOG_CRITICAL, "Here is the peer %p, and arguments follow:", peer);
        //bson_visit("Sandbox passthrough peer not found, args:", args);
        return;
    }
    
    if ( !sandbox_has_peer(sandbox, peer) ) {
        rpc_server_error_msg(req, 55, "Peer not found.");
        return;
    }
    
    // create a bson request with:
    //
    // { op: (copy parent op),
    //   args: [parent args splice(1)] 
    //   id: copy parent id }
    //
    // Then send to passthrough
    
    uint8_t buf[MIST_RPC_REPLY_BUF_LEN];
    bson b;
    bson_init_buffer(&b, buf, MIST_RPC_REPLY_BUF_LEN);
    
    // skip the prefix "sandbox.mist." from op string when forwarding request
    if (memcmp(req->op, "sandboxed.mist.", 10+5) == 0) {
        bson_append_string(&b, "op", req->op+10+5);
    } else {
        rpc_server_error_msg(req, 58, "Unrecognized sandbox command in passthrough. Should start with 'sandbox.mist.' !");
        return;
    }
    
    bson_append_start_array(&b, "args");

    // Only single digit array index supported. 
    //   i.e Do not exceed 7 with the index. Rewrite indexing if you must!
    
    //   bson_find_from_buffer(&it, args, "1");
    //   bson_append_element(&b, "0", &it);
    //   bson_find_from_buffer(&it, args, "2");
    //   bson_append_element(&b, "1", &it);
    //   .
    //   .
    //   .
    
    int i;
    int args_len = 0;
    
    for(i=0; i<8; i++) {
        char src[21];
        char dst[21];
    
        BSON_NUMSTR(src, i+2);
        BSON_NUMSTR(dst, i);
        
        // read the argument
        bson_find_from_buffer(&it, args, src);
        bson_type type = bson_iterator_type(&it);

        if (type == BSON_EOO) {
            break;
        } else {
            bson_append_element(&b, dst, &it);
        }
        
        args_len++;
    }
    
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    rpc_client_callback cb = req->ctx;
    
    // FIXME: this is a memory leak
    app_peer_t* app_peer = wish_platform_malloc(sizeof(app_peer_t));
    app_peer->app = mist_api->wish_app;
    app_peer->peer = peer;

    rpc_client* peer_client = &mist_api->mist_app->protocol.rpc_client;
    // Update the send_ctx for each call to passthrough. This is required because 
    // there is not own clients for each remote peer as there "shuold" be.
    peer_client->send_ctx = app_peer;

    req->end = sandbox_passthrough_end;
    
    rpc_client_req* client_req = rpc_server_passthru(req, peer_client, &b, cb);
    client_req->passthru_ctx2 = sandbox;
}

void sandbox_methods(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    rpc_handler* h = mist_api->server->handlers;
    
    bson bs; 
    bson_init(&bs);
    bson_append_start_object(&bs, "data");
    
    while (h != NULL) {
        if (memcmp(h->op, "sandboxed.", 10) == 0) {
            bson_append_start_object(&bs, h->op+10);
            bson_append_finish_object(&bs);
        }

        h = h->next;
    }
    
    bson_append_finish_object(&bs);
    bson_finish(&bs);
    
    rpc_server_send(req, bs.data, bson_size(&bs));
    bson_destroy(&bs);
}

void sandbox_signals(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "sandbox.signals request, added to subscription list!");

    int buffer_len = 300;
    uint8_t buffer[buffer_len];
    
    bson bs;
    bson_init_buffer(&bs, buffer, buffer_len);
    bson_append_start_array(&bs, "data");
    bson_append_string(&bs, "0", "ok");
    bson_append_finish_array(&bs);
    bson_finish(&bs);

    rpc_server_emit(req, bson_data(&bs), bson_size(&bs));

    if (mist_api->wish_app->ready_state) {
        bson_init_buffer(&bs, buffer, buffer_len);
        bson_append_start_array(&bs, "data");
        bson_append_string(&bs, "0", "ready");
        bson_append_bool(&bs, "1", mist_api->wish_app->ready_state);
        bson_append_finish_array(&bs);
        bson_finish(&bs);

        rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    }
}

void mist_sandbox_list(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.list");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_t* elt;

    DL_FOREACH(mist_api->sandbox_db, elt) {
        //WISHDEBUG(LOG_CRITICAL, "  * a sandbox: %02x %02x %02x %p", elt->sandbox_id[0], elt->sandbox_id[1], elt->sandbox_id[2], elt);
        bson_append_start_object(&bs, "0");
        bson_append_string_maxlen(&bs, "name", elt->name, SANDBOX_NAME_LEN);
        bson_append_binary(&bs, "id", elt->sandbox_id, SANDBOX_ID_LEN);
        bson_append_bool(&bs, "online", elt->online);
        bson_append_finish_object(&bs);
        
        if (bs.err) {
            WISHDEBUG(LOG_CRITICAL, "  bs.err %s", bs.errstr);
            break;
        }
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

#define SANDBOX_FILE   "sandbox.bin"
 
static void mist_sandbox_write_file(const char* buf, int buf_len) {
    wish_fs_remove(SANDBOX_FILE);
    wish_file_t fd = wish_fs_open(SANDBOX_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Sandbox state could not be saved.");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    wish_fs_write(fd, buf, buf_len);
    wish_fs_close(fd);
}

void sandbox_save(mist_api_t* mist_api) {
    //WISHDEBUG(LOG_CRITICAL, "Saving sandbox states:");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_t* sandbox;
    int i = 0;
    
    DL_FOREACH(mist_api->sandbox_db, sandbox) {
        // sandbox string index
        char si[21];
        BSON_NUMSTR(si, i);

        bson_append_start_object(&bs, si);
        bson_append_string_maxlen(&bs, "name", sandbox->name, SANDBOX_NAME_LEN);
        bson_append_binary(&bs, "id", sandbox->sandbox_id, SANDBOX_ID_LEN);
        bson_append_start_array(&bs, "peers");
        
        sandbox_peers_t* p;
        //WISHDEBUG(LOG_CRITICAL, "  about to add peer.");

        // peer index and string index
        int pi = 0;
        char spi[21];

        DL_FOREACH(sandbox->peers, p) {
            BSON_NUMSTR(spi, pi);
            bson_append_start_object(&bs, spi);
            bson_append_binary(&bs, "luid", p->peer.luid, WISH_UID_LEN);
            bson_append_binary(&bs, "ruid", p->peer.ruid, WISH_UID_LEN);
            bson_append_binary(&bs, "rhid", p->peer.rhid, WISH_UID_LEN);
            bson_append_binary(&bs, "rsid", p->peer.rsid, WISH_UID_LEN);
            bson_append_string_maxlen(&bs, "protocol", p->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN);
            bson_append_finish_object(&bs);
            pi++;
        }
        
        bson_append_finish_array(&bs);
        bson_append_finish_object(&bs);
        i++;
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //WISHDEBUG(LOG_CRITICAL, "  about write sandbox file:");
    //bson_visit((char*)bson_data(&bs), elem_visitor);
    
    mist_sandbox_write_file( bson_data(&bs), bson_size(&bs) );
    bson_destroy(&bs);
}

void mist_sandbox_remove(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.list");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);    
    
    sandbox_t* elt;
    sandbox_t* tmp;

    bool deleted = false;
    
    LL_FOREACH_SAFE(mist_api->sandbox_db, elt, tmp) {
        
        if ( memcmp(elt->sandbox_id, sandbox_id, SANDBOX_ID_LEN) == 0 ) {
            
            sandbox_peers_t* p;
            sandbox_peers_t* ptmp;
            
            LL_FOREACH_SAFE(elt->peers, p, ptmp) {
                if (p != NULL) { wish_platform_free(p); }
            }
            
            LL_DELETE(mist_api->sandbox_db, elt);
            
            wish_platform_free(elt);
            
            deleted = true;
            break;
        }
    }
    
    sandbox_save(mist_api);
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", deleted);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    bson_destroy(&bs);
}


/**
 * BSON.deserialize(fs.readFileSync('./sandbox.bin'))
 * { data: 
 *    [ { name: 'ControlThings App',
 *        id: <Buffer be ef 00 ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab>,
 *        peers: [] },
 *      { name: 'Soikea App',
 *        id: <Buffer de ad 00 ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab ab>,
 *        peers: 
 *         [ { luid: <Buffer 45 07 9c 1a 9a 15 4c 55 4c 27 62 9d c5 a6 30 3c f3 01 85 c2 3a 23 6a 33 b6 18 3b 35 35 31 43 c9>,
 *             ruid: <Buffer 45 07 9c 1a 9a 15 4c 55 4c 27 62 9d c5 a6 30 3c f3 01 85 c2 3a 23 6a 33 b6 18 3b 35 35 31 43 c9>,
 *             rhid: <Buffer 0e b9 2d bf 29 a8 49 53 b9 36 9f 11 9a 2d 94 97 6a a0 33 ac 33 55 d5 ae f7 ed ff 07 2e 20 68 3b>,
 *             rsid: <Buffer 47 50 53 20 6e 6f 64 65 2e 6a 73 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00>,
 *             protocol: 'ucp' } ] } ] }
 */
void sandbox_load(mist_api_t* mist_api) {
    wish_file_t fd = wish_fs_open(SANDBOX_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Sandbox could not be loaded!");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    
    
    int size = 0;
    
    /* First, read in the next mapping id */
    int read_ret = wish_fs_read(fd, (void*) &size, 4);

    if (read_ret != 4) {
        //WISHDEBUG(LOG_CRITICAL, "Empty file, or read error in sandbox load.");
        return;
    }

    if(size>64*1024) {
        WISHDEBUG(LOG_CRITICAL, "Sandbox load, file too large (64KiB limit). Found: %i bytes.", size);
        return;
    }
    
    bson bs;
    bson_init_size(&bs, size);
    
    /* Go back to start and read the whole file to bson buffer */
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    read_ret = wish_fs_read(fd, ((void*)bs.data), size);
    
    if (read_ret != size) {
        WISHDEBUG(LOG_CRITICAL, "Sandbox failed to read %i bytes, got %i.", size, read_ret);
    }
    
    wish_fs_close(fd);
    
    //WISHDEBUG(LOG_CRITICAL, "Sandbox file loaded this:");
    //bson_visit( (char*) bson_data(&bs), elem_visitor);

    /* Load content from sandbox file */
    
    bson_iterator it;
    bson_iterator sit;
    bson_iterator soit;
    bson_iterator pit;
    bson_iterator poit;
    
    if ( bson_find(&it, &bs, "data") != BSON_ARRAY ) {
        // that didn't work
        WISHDEBUG(LOG_CRITICAL, "That didn't work d. %i", bson_find(&sit, &bs, "data"));
        bson_destroy(&bs);
        return;
    }
    
    // sandbox index
    int si = 0;
    char sindex[21];
    
    while (true) {
        BSON_NUMSTR(sindex, si++);
        
        bson_iterator_subiterator(&it, &sit);
        if ( bson_find_fieldpath_value(sindex, &sit) != BSON_OBJECT ) {
            // that didn't work
            //WISHDEBUG(LOG_CRITICAL, "Not an object at index %s looking for sandboxes.", sindex);
            bson_destroy(&bs);
            return;
        }
        
        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("name", &soit) != BSON_STRING ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work b.");
            bson_destroy(&bs);
            return;
        }

        const char* name = bson_iterator_string(&soit);

        //WISHDEBUG(LOG_CRITICAL, "A sandbox name: %s", name);

        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("id", &soit) != BSON_BINDATA || bson_iterator_bin_len(&soit) != WISH_UID_LEN ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work c.");
            bson_destroy(&bs);
            return;
        }

        const char* id = bson_iterator_bin_data(&soit);

        //WISHDEBUG(LOG_CRITICAL, "A sandbox id: %02x %02x %02x %02x", id[0], id[1], id[2], id[3]);

        bson_iterator_subiterator(&sit, &soit);

        if ( bson_find_fieldpath_value("peers", &soit) != BSON_ARRAY ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "That didn't work d.");
            bson_destroy(&bs);
            return;
        }


        /* We have confirmed there is a sandbox object here */
        sandbox_t* sandbox = wish_platform_malloc(sizeof(sandbox_t));

        if (!sandbox) {
            WISHDEBUG(LOG_CRITICAL, "Memory allocation failed.");
            bson_destroy(&bs);
            return;
        }

        memset(sandbox, 0, sizeof(sandbox_t));
        memcpy(sandbox->sandbox_id, id, SANDBOX_ID_LEN);
        strncpy(sandbox->name, name, SANDBOX_NAME_LEN);
        sandbox->online = false;

        LL_APPEND(mist_api->sandbox_db, sandbox);


        int pi = 0;
        char pindex[21];

        while (true) {
            BSON_NUMSTR(pindex, pi++);
            bson_iterator_subiterator(&soit, &pit);
            if ( bson_find_fieldpath_value(pindex, &pit) != BSON_OBJECT ) {
                // that didn't work
                //WISHDEBUG(LOG_CRITICAL, "No index %s looking for peers in %s.", pindex, name);
                break;
            }

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("luid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work luid."); break; }
            const char* luid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("ruid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work ruid."); break; }
            const char* ruid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("rhid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work rhid."); break; }
            const char* rhid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("rsid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work rsid."); break; }
            const char* rsid = bson_iterator_bin_data(&poit);

            bson_iterator_subiterator(&pit, &poit);
            if ( bson_find_fieldpath_value("protocol", &poit) != BSON_STRING || bson_iterator_string_len(&poit) > WISH_PROTOCOL_NAME_MAX_LEN ) { 
                WISHDEBUG(LOG_CRITICAL, "That didn't work protocol."); break; }
            const char* protocol = bson_iterator_string(&poit);

            //WISHDEBUG(LOG_CRITICAL, "Got all the way here. %s", protocol);

            /* We have confirmed there is a peer object here */
            sandbox_peers_t* peer_elt = wish_platform_malloc(sizeof(sandbox_peers_t));

            if (!peer_elt) {
                WISHDEBUG(LOG_CRITICAL, "Memory allocation failed for peer.");
                bson_destroy(&bs);
                return;
            }

            memset(peer_elt, 0, sizeof(sandbox_peers_t));

            memcpy(&peer_elt->peer.luid, luid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.ruid, ruid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.rhid, rhid, WISH_UID_LEN);
            memcpy(&peer_elt->peer.rsid, rsid, WISH_UID_LEN);
            strncpy(peer_elt->peer.protocol, protocol, WISH_PROTOCOL_NAME_MAX_LEN);

            LL_PREPEND(sandbox->peers, peer_elt);
        }
    }
    
    bson_destroy(&bs);
}

void sandbox_signals_emit(mist_api_t* mist_api, char* signal) {
    int buf_len = 300;
    char buf[buf_len];
    
    bson b;
    bson_init_buffer(&b, buf, buf_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", signal);
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
}

void mist_sandbox_add_peer(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.addPeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    bson_find_from_buffer(&it, args, "1");
    
    wish_protocol_peer_t peer;
    
    bool success = wish_protocol_peer_populate_from_bson(&peer, (uint8_t*) bson_iterator_value(&it));
    
    if ( success ) {
        // try to find the peer in the db
        wish_protocol_peer_t* actual = mist_api_peer_find(mist_api, &peer);
        
        if (actual != NULL) {
            peer.online = actual->online;
        }
        
        sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
        
        if (sandbox == NULL) {
            rpc_server_error_msg(req, 58, "Sandbox not found.");
            return;
        }
        
        bool added = sandbox_add_peer(sandbox, &peer);
        
        bson bs;
        bson_init(&bs);
        bson_append_bool(&bs, "data", added);
        bson_finish(&bs);
        rpc_server_send(req, bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);

        if (added) { sandbox_signals_emit(mist_api, "peers"); }
    } else {
        //WISHDEBUG(LOG_CRITICAL, "  Peer invalid.");
        //bson_visit(args, elem_visitor);
        rpc_server_error_msg(req, 57, "Peer invalid.");
    }
    
    sandbox_save(mist_api);
}

void mist_sandbox_remove_peer(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.removePeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 32) {
        rpc_server_error_msg(req, 58, "Sandbox id invalid.");
        return;
    }
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    bson_find_from_buffer(&it, args, "1");
    
    wish_protocol_peer_t peer;
    
    bool success = wish_protocol_peer_populate_from_bson(&peer, (uint8_t*) bson_iterator_value(&it));
    
    if ( success ) {
        // try to find the peer in the db
        wish_protocol_peer_t* actual = mist_api_peer_find(mist_api, &peer);
        
        if (actual == NULL) {
            // there is no actual peer that corresponds to the sandboxed peer
        } else {
            peer.online = actual->online;
        }        
        
        sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
        
        if (sandbox == NULL) {
            rpc_server_error_msg(req, 58, "Sandbox not found.");
            return;
        }
        
        bool removed = sandbox_remove_peer(sandbox, &peer);
        
        bson bs;
        bson_init(&bs);
        bson_append_bool(&bs, "data", removed);
        bson_finish(&bs);
        rpc_server_send(req, bson_data(&bs), bson_size(&bs));
        bson_destroy(&bs);

        if (removed) { sandbox_signals_emit(mist_api, "peers"); }
    } else {
        //WISHDEBUG(LOG_CRITICAL, "  Peer invalid.");
        //bson_visit(args, elem_visitor);
        rpc_server_error_msg(req, 57, "Peer invalid.");
    }
    
    sandbox_save(mist_api);
}

static void sandbox_passthru_cb(rpc_client_req* creq, void *ctx, const uint8_t *payload, size_t payload_len) {
    rpc_server_req* req = ctx;
    
    if (creq->err) {
        rpc_server_error(req, payload, payload_len);
        return;
    }
    
    if (creq->sig) {
        rpc_server_emit(req, payload, payload_len);
        return;
    }
    
    rpc_server_send(req, payload, payload_len);
}

static void sandbox_wish_request(rpc_server_req* req, const char* op, const uint8_t* args) {
    mist_api_t* mist_api = req->server->context;
    
    bson_iterator it;
    
    bson b;
    bson_init(&b);

    bson_append_string(&b, "op", op);
    bson_append_start_array(&b, "args");

    bson_find_from_buffer(&it, args, "1");

    int i = 0;
    char index[21];
    // Skip first two argument and take all other arguments
    while (BSON_EOO != bson_iterator_next(&it)) {
        BSON_NUMSTR(index, i++);
        bson_append_element(&b, index, &it);
    }

    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    req->end = sandbox_passthrough_end;

    rpc_server_passthru(req, &mist_api->mist_app->app->rpc_client, &b, sandbox_passthru_cb);
    bson_destroy(&b);
}

static void sandbox_wish_connections_request(rpc_server_req* req, const char* op, const uint8_t* args) {
    mist_api_t* mist_api = req->server->context;

    bson_iterator it;
    
    bson_type t = bson_find_from_buffer(&it, args, "1");
    
    if (t != BSON_OBJECT) {
        rpc_server_error_msg(req, 58, "Core id not object Peer/Connection.");
        return;
    }
    
    bson b;
    bson_init(&b);

    bson_append_string(&b, "op", "connections.request");
    bson_append_start_array(&b, "args");

    bson_append_element(&b, "0", &it);

    bson_append_string(&b, "1", op);
    bson_append_start_array(&b, "2");

    bson_find_from_buffer(&it, args, "1");

    int i = 0;
    char index[21];
    // Skip first two argument and take all other arguments
    while (BSON_EOO != bson_iterator_next(&it)) {
        BSON_NUMSTR(index, i++);
        bson_append_element(&b, index, &it);
    }

    bson_append_finish_array(&b);

    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    bson_finish(&b);

    req->end = sandbox_passthrough_end;

    //bson_visit("connections.request:", bson_data(&b));
    
    rpc_server_passthru(req, &mist_api->mist_app->app->rpc_client, &b, sandbox_passthru_cb);
    bson_destroy(&b);
}

/**
 * Responds with errors to req and returns sandbox_t* or NULL on failure
 * 
 * @param req
 * @param args
 * @return sandbox_t*
 */
static sandbox_t* sandbox_from_args(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = req->server->context;
    
    bson_iterator it;
    
    if ( BSON_BINDATA != bson_find_from_buffer(&it, args, "0") ) {
        rpc_server_error_msg(req, 455, "Invalid sandbox id.");
        return NULL;
    }

    if ( SANDBOX_ID_LEN != bson_iterator_bin_len(&it) ) {
        rpc_server_error_msg(req, 58, "Invalid sandbox id length.");
        return NULL;
    }
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
    
    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return NULL;
    }
    
    return sandbox;    
}
    
static void sandbox_friend_request_cb(rpc_client_req* req, void *ctx, const uint8_t *payload, size_t payload_len) {
    mist_api_t* mist_api = req->client->context;
    //bson_visit("sandbox_friend_request_cb", payload);
}


void mist_sandbox_allow_request(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    bson_iterator it;
    
    sandbox_t* sandbox = sandbox_from_args(req, args);

    if (sandbox == NULL) { return; }
    
    const char* luid = NULL;
    const char* ruid = NULL;
    const char* rhid = NULL;
    const char* rsid = NULL;
    const char* protocol = NULL;
    int protocol_len = 0;
    bool sandboxed_peer_friend_request = true;

    bson_iterator_from_buffer(&it, args);
    
    // find id from arguments "1" or "1.id"
    if (BSON_INT != bson_find_fieldpath_value("1.id", &it)) {
        rpc_server_error_msg(req, 61, "Request id not found. (1.id)");
        return;
    }
    
    int id = bson_iterator_int(&it);
    
    rpc_server_req* sreq = rpc_server_req_by_id(mist_api->server, id);
    
    if (sreq == NULL) {
        rpc_server_error_msg(req, 61, "Request id not found.");
        return;
    }
    
    bson_iterator_from_buffer(&it, args);
    
    // 1.op
    if (BSON_STRING != bson_find_fieldpath_value("1.op", &it)) {
        rpc_server_error_msg(req, 61, "Invalid op");
        rpc_server_error_msg(sreq, 61, "Invalid op.");
        return;
    }

    if ( !(strcmp("identity.friendRequest", bson_iterator_string(&it)) == 0 || strcmp("identity.friendRequestList", bson_iterator_string(&it)) == 0) ) {
        WISHDEBUG(LOG_CRITICAL, "Unsupported op: %s", bson_iterator_string(&it));
        rpc_server_error_msg(req, 61, "Unsupported op");
        rpc_server_error_msg(sreq, 61, "Unsupported op or permission denied.");
        return;
    }

    //bson_visit("sandbox_allow_request:", args);

    
    //luid 1.args.0
    bson_iterator_from_buffer(&it, args);
    
    if (BSON_BINDATA != bson_find_fieldpath_value("1.args.0", &it)) {
        //rpc_server_error_msg(req, 61, "invalid uid");
        //return;
        sandboxed_peer_friend_request = false;
    }
    
    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        //rpc_server_error_msg(req, 61, "invalid uid len");
        //return;
        sandboxed_peer_friend_request = false;
    }
    
    if (sandboxed_peer_friend_request) {
        luid = bson_iterator_bin_data(&it);
    }
    
    // cert 1.args.1
    bson_iterator_from_buffer(&it, args);
    
    if (BSON_OBJECT != bson_find_fieldpath_value("1.args.1", &it)) {
        //rpc_server_error_msg(req, 61, "invalid cert");
        //return;
        sandboxed_peer_friend_request = false;
    }
    
    if (sandboxed_peer_friend_request) {

        bson_iterator sit;
        bson_iterator_subiterator(&it, &sit);

        if (BSON_BINDATA != bson_find_fieldpath_value("data", &sit)) {
            //rpc_server_error_msg(req, 61, "invalid cert.data");
            //return;
            sandboxed_peer_friend_request = false;
        }

        //bson_visit("cert.data", bson_iterator_bin_data(&sit));

        bson_iterator cit;

        if ( BSON_BINDATA != bson_find_from_buffer(&cit, bson_iterator_bin_data(&sit), "uid") ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.uid");
            //return;
            sandboxed_peer_friend_request = false;
        }

        if ( WISH_WHID_LEN != bson_iterator_bin_len(&cit) ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.uid len");
            //return;
            sandboxed_peer_friend_request = false;
        }

        if (sandboxed_peer_friend_request) {
            ruid = bson_iterator_bin_data(&cit);
        }

        if ( BSON_BINDATA != bson_find_from_buffer(&cit, bson_iterator_bin_data(&sit), "hid") ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.hid");
            //return;
            sandboxed_peer_friend_request = false;
        }

        if ( WISH_WHID_LEN != bson_iterator_bin_len(&cit) ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.hid len");
            //return;
            sandboxed_peer_friend_request = false;
        }

        rhid = bson_iterator_bin_data(&cit);

        if ( BSON_BINDATA != bson_find_from_buffer(&cit, bson_iterator_bin_data(&sit), "sid") ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.sid");
            //return;
            sandboxed_peer_friend_request = false;
        }

        if ( WISH_WSID_LEN != bson_iterator_bin_len(&cit) ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.sid len");
            //return;
            sandboxed_peer_friend_request = false;
        }

        rsid = bson_iterator_bin_data(&cit);

        if ( BSON_STRING != bson_find_from_buffer(&cit, bson_iterator_bin_data(&sit), "protocol") ) {
            //rpc_server_error_msg(req, 61, "invalid cert.data.protocol");
            //return;
            sandboxed_peer_friend_request = false;
        }

        if (sandboxed_peer_friend_request) {
            protocol = bson_iterator_string(&cit);
            protocol_len = bson_iterator_string_len(&cit);

            wish_protocol_peer_t peer;
            memset(&peer, 0, sizeof(wish_protocol_peer_t));

            memcpy(peer.luid, luid, WISH_UID_LEN);
            memcpy(peer.ruid, ruid, WISH_UID_LEN);
            memcpy(peer.rhid, rhid, WISH_WHID_LEN);
            memcpy(peer.rsid, rsid, WISH_WSID_LEN);
            strncpy(peer.protocol, protocol, protocol_len);

            wish_protocol_peer_t* actual = mist_api_peer_find(mist_api, &peer);

            if (actual != NULL) {
                peer.online = actual->online;
            }

            // sandbox.addPeer()
            bool added = sandbox_add_peer(sandbox, &peer);
            sandbox_save(mist_api);
        }
    }
    
    // make request 
    bson_iterator_from_buffer(&it, args);
    
    if (BSON_OBJECT != bson_find_fieldpath_value("1", &it)) {
        rpc_server_error_msg(req, 61, "Invalid request");
        return;
    }
    
    bson br;
    bson_init_with_data(&br, bson_iterator_value(&it));

    wish_api_request(mist_api, &br, sandbox_friend_request_cb);


    // respond to allow request
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void mist_sandbox_deny_request(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 32) {
        rpc_server_error_msg(req, 58, "Sandbox id invalid.");
        return;
    }
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);

    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    bson_iterator_from_buffer(&it, args);
    
    bson_visit("sandbox.denyRequest (1.id or 1)", args);
    
    // find id from arguments "1" or "1.id"
    if (BSON_INT != bson_find_fieldpath_value("1.id", &it)) {
        bson_iterator_from_buffer(&it, args);
        if (BSON_INT != bson_find_fieldpath_value("1", &it)) {
            rpc_server_error_msg(req, 61, "Invalid id.");
            return;
        } else {
            // found id in "1"
        }
        // found id in "1.id"
    }
    
    int id = bson_iterator_int(&it);
    
    rpc_server_req* sreq = rpc_server_req_by_id(mist_api->server, id);
    
    if (sreq == NULL) {
        rpc_server_error_msg(req, 61, "Request id not found.");
        return;
    }
    
    rpc_server_error_msg(sreq, 43, "Permission denied.");
    
    // send response to deny_request caller
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void mist_sandbox_emit(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 32) {
        rpc_server_error_msg(req, 58, "Sandbox id invalid.");
        return;
    }
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);

    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }
    
    const char* signal = NULL;
    
    if (BSON_STRING != bson_find_from_buffer(&it, args, "1")) {
        rpc_server_error_msg(req, 78, "Signal name must be string.");
        return;
    }
    
    signal = bson_iterator_string(&it);

    bson_iterator_from_buffer(&it, args);

    bson b;
    bson_init(&b);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", signal);
    if (BSON_EOO != bson_find_fieldpath_value("2", &it)) {
        bson_append_element(&b, "1", &it);
    }
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    rpc_server_emit_broadcast(mist_api->server, "sandboxed.signals", bson_data(&b), bson_size(&b));
    bson_destroy(&b);
    
    // send response to deny_request caller
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void sandbox_list_peers(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.listPeers");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");
    
    sandbox_peers_t* elt;
    int c = 0;
    
    DL_FOREACH(sandbox->peers, elt) {
        char s[21];
        bson_numstr(s, c++);
        bson_append_start_object(&bs, s);
        bson_append_binary(&bs, "luid", elt->peer.luid, 32);
        bson_append_binary(&bs, "ruid", elt->peer.ruid, 32);
        bson_append_binary(&bs, "rhid", elt->peer.rhid, 32);
        bson_append_binary(&bs, "rsid", elt->peer.rsid, 32);
        bson_append_string(&bs, "protocol", elt->peer.protocol);
        bson_append_bool(&bs, "online", elt->peer.online);
        bson_append_finish_object(&bs);
    }

    bson_append_finish_array(&bs);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void sandbox_commission_list(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    if (BSON_STRING == bson_find_from_buffer(&it, args, "1") ) {
        //commission_list_filter = strdup(bson_iterator_string(&it));
        commission_set_filter(req, (char*) bson_iterator_string(&it));
    } else {
        //commission_list_filter = NULL;
        commission_set_filter(req, NULL);
    }
    
    bson b;
    bson_init(&b);
    bson_append_string(&b, "op", "wld.list");
    bson_append_start_array(&b, "args");
    bson_append_finish_array(&b);
    bson_append_int(&b, "id",req->id);
    bson_finish(&b);
    
    rpc_server_passthru(req, &mist_api->mist_app->app->rpc_client, &b, commission_wld_list_cb);
    bson_destroy(&b);
}

/*
 [
  { type: 'wifi', ssid: 'mist-315 S. Broad St.' },
  { type: 'local',
    alias: 'Alice',
    ruid: <Buffer 5f 5e ... 9e 14>,
    rhid: <Buffer 46 ad ... 68 79>,
    pubkey: <Buffer 4c 9f ... 82 36>,
    class: 'fi.ct.neatdevice' } ] 
*/

void sandbox_commission_perform(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    // start new commission state machine
    
    // wifi: need ssid, [password]
    // wld: ruid, rhid

    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_BINDATA != bson_find_fieldpath_value("1", &it) ) {
        rpc_server_error_msg(req, 667, "Commission luid invalid.");
        return;
    }
    
    const char* luid = bson_iterator_bin_data(&it);
    
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("2.type", &it) ) {
        rpc_server_error_msg(req, 667, "Commission type not string.");
        return;
    }
    
    const char* type = bson_iterator_string(&it);
    
    if (strncmp("wifi", type, 5) == 0) {
        bson_iterator_from_buffer(&it, args);

        if ( BSON_STRING != bson_find_fieldpath_value("2.ssid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission wifi ssid not string.");
            return;
        }

        const char* ssid = bson_iterator_string(&it);

        bson_iterator_from_buffer(&it, args);
        
        const char* password = NULL;
        
        if ( BSON_STRING == bson_find_fieldpath_value("2.password", &it) ) {
            password = bson_iterator_string(&it);
        }

        const char* class = NULL;
        
        bson_iterator_from_buffer(&it, args);
        
        if ( BSON_STRING == bson_find_fieldpath_value("2.class", &it) ) {
            class = bson_iterator_string(&it);
        }

        mist_api->commissioning.req_sid = req->sid;
        mist_api->commissioning.sandbox_id = wish_platform_malloc(SANDBOX_ID_LEN);
        memcpy(mist_api->commissioning.sandbox_id, sandbox_id, SANDBOX_ID_LEN);
        mist_api->commissioning.via_sandbox = true;
        
        // do the wifi thing, try to join the wifi given
        commission_event_start_wifi(mist_api, luid, ssid, password, class);
        
        //mist_port_wifi_join(ssid, NULL);
    } else if (strncmp("local", type, 6) == 0) {
        // do the local thing, send friend request and wait for response
        
        bson_iterator_from_buffer(&it, args);

        if ( BSON_BINDATA != bson_find_fieldpath_value("2.ruid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission ruid not buffer.");
            return;
        }

        const char* ruid = bson_iterator_bin_data(&it);
        
        bson_iterator_from_buffer(&it, args);

        if ( BSON_BINDATA != bson_find_fieldpath_value("2.rhid", &it) ) {
            rpc_server_error_msg(req, 667, "Commission rhid not buffer.");
            return;
        }

        const char* rhid = bson_iterator_bin_data(&it);
        
        bson_iterator_from_buffer(&it, args);
        
        const char* class = NULL;
        
        if ( BSON_STRING == bson_find_fieldpath_value("2.class", &it) ) {
            class = bson_iterator_string(&it);
        }
        
        mist_api->commissioning.req_sid = req->sid;
        mist_api->commissioning.sandbox_id = wish_platform_malloc(SANDBOX_ID_LEN);
        memcpy(mist_api->commissioning.sandbox_id, sandbox_id, SANDBOX_ID_LEN);
        mist_api->commissioning.via_sandbox = true;
        
        commission_event_start_wld(mist_api, luid, ruid, rhid, class);
    } else {
        rpc_server_error_msg(req, 667, "Commission type unknown, expecting wifi or local.");
        return;
    }
    
    /*
    // emit progress
    bson bs;
    bson_init(&bs);
    bson_append_int(&bs, "data", mist_api->commissioning.state);
    bson_finish(&bs);
    
    rpc_server_emit(req, bson_data(&bs), bson_size(&bs));
    //rpc_server_emit_broadcast(req->server, "commission.perform", bson_data(), bson_size());
    
    bson_destroy(&bs);
    */
    
    //rpc_server_error_msg(req, 101, "Not implemented.");
}

/*
 * args: [sandboxId, ssid, password]
 */
void sandbox_commission_select_wifi(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);

    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    // start new commission state machine
    
    // wifi: need ssid, [password]
    // wld: ruid, rhid

    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("1.type", &it) ) {
        rpc_server_error_msg(req, 668, "Type must be string.");
        return;
    }
    
    const char* type = bson_iterator_string(&it);
    
    bson_iterator_from_buffer(&it, args);
    
    if ( BSON_STRING != bson_find_fieldpath_value("1.ssid", &it) ) {
        rpc_server_error_msg(req, 668, "SSID must be string.");
        return;
    }
    
    const char* ssid = bson_iterator_string(&it);
    
    bson_iterator_from_buffer(&it, args);
    const char* password = NULL;
    
    if ( BSON_STRING == bson_find_fieldpath_value("1.password", &it) ) {
        password = bson_iterator_string(&it);
        //rpc_server_error_msg(req, 668, "Password must be string");
        //return;
    }

    
    commission_event_select_wifi(mist_api, type, ssid, password);
    
    // respond
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    
    bson_destroy(&bs);
}

void sandbox_settings(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //WISHDEBUG(LOG_CRITICAL, "mist.sandbox.addPeer");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    bson_type bt = bson_find_from_buffer(&it, args, "1");
    
    if ( !(BSON_STRING == bt || BSON_EOO == bt) ) {
        rpc_server_error_msg(req, 571, "Hint name must be string or undefined");
        return;
    }
    
    int hint_max_len = 32;
    char* hint = (char*) bson_iterator_string(&it);
    if (strnlen(hint, hint_max_len) == 0) { hint = NULL; }

    int buffer_len = 512;
    uint8_t buffer[buffer_len];
    
    bson b;
    bson_init_buffer(&b, buffer, buffer_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "sandboxed.settings");
    bson_append_start_object(&b, "1");
    bson_append_binary(&b, "id", sandbox_id, SANDBOX_ID_LEN);
    
    if (hint != NULL) {
        bson_append_string_maxlen(&b, "hint", hint, hint_max_len);
    }
    
    //WISHDEBUG(LOG_CRITICAL, "BSON type in hint arg %d", bson_find_from_buffer(&it, args, "2"));
    
    if (BSON_EOO != bson_find_from_buffer(&it, args, "2")) {
        bson_append_element(&b, "opts", &it);
    }

    bson_append_finish_object(&b);
    bson_append_finish_array(&b);
    bson_finish(&b);
    
    if (b.err) {
        WISHDEBUG(LOG_CRITICAL, "Error producing signal from hint %d", b.err);
        rpc_server_error_msg(req, 571, "Error producing signal from hint");
        return;
    }

    rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));
    
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

static void sandbox_delete_outstanding_reqs(sandbox_t* sandbox, rpc_client* client) {
    rpc_client_req* entry = client->requests;
    while (entry != NULL) {
        // save next pointer as it will be deleted
        rpc_client_req* next = entry->next;
        
        if (entry->passthru_ctx2 == sandbox) {
            rpc_client_end_by_id(client, entry->id);
        }
        
        entry = next;
    }
}

void sandbox_login(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;

    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }
    
    bool changed = false;
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    if (bson_iterator_type(&it) != BSON_BINDATA || bson_iterator_bin_len(&it) != 32) {
        rpc_server_error_msg(req, 88, "Invalid sandbox id");
        return;
    }
    
    char* id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, id);

    if (sandbox == NULL) {
        sandbox = wish_platform_malloc(sizeof(sandbox_t));

        if (!sandbox) {
            rpc_server_error_msg(req, 102, "Memory allocation failed.");
            return;
        }

        memset(sandbox, 0, sizeof(sandbox_t));
        memcpy(sandbox->sandbox_id, id, SANDBOX_ID_LEN);
        
        LL_PREPEND(mist_api->sandbox_db, sandbox);
        changed = true;
    }
    
    sandbox_delete_outstanding_reqs(sandbox, &mist_api->mist_app->protocol.rpc_client);

    bson_find_from_buffer(&it, args, "1");
    char* name = (char*) bson_iterator_string(&it);

    if ( strncmp(sandbox->name, name, SANDBOX_NAME_LEN) != 0 ) {
        changed = true;
    }
    
    strncpy(sandbox->name, name, SANDBOX_NAME_LEN);
    sandbox->online = true;

    if (changed) {
        sandbox_save(mist_api);
    }
    
    bson b;
    bson_init(&b);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "sandboxed.login");
    bson_append_start_object(&b, "1");
    bson_append_binary(&b, "id", id, SANDBOX_ID_LEN);
    bson_append_finish_object(&b);
    bson_append_finish_array(&b);
    bson_finish(&b);

    rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));
    bson_destroy(&b);
    
    
    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void sandbox_logout(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satify request because mist_api->wish_app is NULL");
        return;
    }

    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
    
    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    sandbox_delete_outstanding_reqs(sandbox, &mist_api->mist_app->protocol.rpc_client);

    sandbox->online = false;
    
    rpc_server_end_by_context(req->server, sandbox);

    bson bs;
    bson_init(&bs);
    bson_append_bool(&bs, "data", true);
    bson_finish(&bs);
    rpc_server_send(req, bson_data(&bs), bson_size(&bs));
    bson_destroy(&bs);
}

void sandbox_wish_passthru(rpc_server_req* req, const uint8_t* args) {
    const char* prefix = "sandboxed.wish.";
    
    if ( memcmp(req->op, prefix, 10+5) != 0) {
        rpc_server_error_msg(req, 79, "Sandbox passthru command not prefixed with sandboxed.wish, bailing out.");
        return;
    }
    
    const char* op = req->op+10+5; // discard "sandboxed.wish." from the beginning
    
    sandbox_t* sandbox = sandbox_from_args(req, args);
    
    if (sandbox == NULL) { return; }

    bson_iterator it;
    
    bson_type t = bson_find_from_buffer(&it, args, "1");
    
    if ( !(t == BSON_NULL || t == BSON_OBJECT) ) {
        rpc_server_error_msg(req, 58, "Core id not null or Peer/Connection.");
        return;
    }

    if ( t == BSON_NULL ) {
        sandbox_wish_request(req, op, args);
        return;
    }
    
    if (t == BSON_OBJECT) {
        sandbox_wish_connections_request(req, op, args);
        return;
    }
}

void sandbox_wish_identity_update(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    //WISHDEBUG(LOG_CRITICAL, "sandbox_wish_identity_update");
    
    const char* op = "identity.update";
    
    sandbox_t* sandbox = sandbox_from_args(req, args);
    
    if (sandbox == NULL) { return; }
    
    bson_iterator it;
    
    if (BSON_BINDATA != bson_find_from_buffer(&it, args, "2")) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    const char* uid = bson_iterator_bin_data(&it);
    
    if (!mist_sandbox_uid_in_peers(mist_api, sandbox, uid)) {
        rpc_server_error_msg(req, 60, "Identity not in sandbox.");
        return;
    }
    
    bson_type t = bson_find_from_buffer(&it, args, "1");
    
    if ( !(t == BSON_NULL || t == BSON_OBJECT) ) {
        rpc_server_error_msg(req, 58, "Core id not null or Peer/Connection.");
        return;
    }

    if ( t == BSON_NULL ) {
        sandbox_wish_request(req, op, args);
        return;
    }
    
    if (t == BSON_OBJECT) {
        sandbox_wish_connections_request(req, op, args);
        return;
    }
}

void sandbox_wish_identity_permissions(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    //WISHDEBUG(LOG_CRITICAL, "sandbox_wish_identity_update");
    
    const char* op = "identity.permissions";
    
    sandbox_t* sandbox = sandbox_from_args(req, args);
    
    if (sandbox == NULL) { return; }
    
    bson_iterator it;
    
    if (BSON_BINDATA != bson_find_from_buffer(&it, args, "2")) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    const char* uid = bson_iterator_bin_data(&it);
    
    if (!mist_sandbox_uid_in_peers(mist_api, sandbox, uid)) {
        rpc_server_error_msg(req, 60, "Identity not in sandbox.");
        return;
    }
    
    bson_type t = bson_find_from_buffer(&it, args, "1");
    
    if ( !(t == BSON_NULL || t == BSON_OBJECT) ) {
        rpc_server_error_msg(req, 58, "Core id not null or Peer/Connection.");
        return;
    }

    if ( t == BSON_NULL ) {
        sandbox_wish_request(req, op, args);
        return;
    }
    
    if (t == BSON_OBJECT) {
        sandbox_wish_connections_request(req, op, args);
        return;
    }
}

void sandbox_wish_identity_sign(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    const char* op = "identity.sign";
    
    sandbox_t* sandbox = sandbox_from_args(req, args);
    
    if (sandbox == NULL) { return; }

    bson_iterator it;
    
    if (BSON_BINDATA != bson_find_from_buffer(&it, args, "2")) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }
    
    const char* uid = bson_iterator_bin_data(&it);
    
    if (!mist_sandbox_uid_in_peers(mist_api, sandbox, uid)) {
        rpc_server_error_msg(req, 60, "Identity not in sandbox.");
        return;
    }
    
    bson_type t = bson_find_from_buffer(&it, args, "1");
    
    if ( !(t == BSON_NULL || t == BSON_OBJECT) ) {
        rpc_server_error_msg(req, 58, "Core id not null or Peer/Connection.");
        return;
    }

    if ( t == BSON_NULL ) {
        sandbox_wish_request(req, op, args);
        return;
    }
    
    if (t == BSON_OBJECT) {
        sandbox_wish_connections_request(req, op, args);
        return;
    }
}

void sandbox_wish_identity_friend_request(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    
    //bson_visit("sandbox_wish_identity_friend_request, args:", args);
    //WISHDEBUG(LOG_CRITICAL, "  sandbox op: %s (id: %d)", req->op, req->id);
    
    const char* op = req->op+10+5; //"wish.identity.friendRequest" discard "sandboxed.wish." from the beginning
    
    bson_iterator it;
    bson_find_from_buffer(&it, args, "0");
    
    char* sandbox_id = (char*) bson_iterator_bin_data(&it);
    
    sandbox_t* sandbox = mist_sandbox_by_id(mist_api, sandbox_id);
    
    if (sandbox == NULL) {
        rpc_server_error_msg(req, 58, "Sandbox not found.");
        return;
    }

    if( BSON_OBJECT == bson_find_from_buffer(&it, args, "1") ) {
        rpc_server_error_msg(req, 60, "Wish Core id is object but remote is not yet supported for sandboxed friendRequests.");
        return;
    }

    if( BSON_NULL != bson_find_from_buffer(&it, args, "1") ) {
        rpc_server_error_msg(req, 60, "Wish Core id is not null");
        return;
    }

    if( BSON_BINDATA != bson_find_from_buffer(&it, args, "2") ) {
        rpc_server_error_msg(req, 60, "Invalid luid.");
        return;
    }
    
    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        rpc_server_error_msg(req, 60, "Invalid luid.");
        return;
    }
    
    const char* luid = bson_iterator_bin_data(&it);


    if( BSON_OBJECT != bson_find_from_buffer(&it, args, "3") ) {
        rpc_server_error_msg(req, 60, "Invalid cert.");
        return;
    }
    
    // emit MistApi signal with hint: { op: 'identity.friendRequest', args: [sandboxId, luid, cert], id: req->id }
    // respond to sandbox with "waiting for approval" or "ok" if user has allowed this sandbox to make friend requests
    
    int buffer_len = 1024+512;
    uint8_t buffer[buffer_len];
    
    bson b;
    bson_init_buffer(&b, buffer, buffer_len);
    bson_append_start_array(&b, "data");
    bson_append_string(&b, "0", "sandboxed.settings");
    bson_append_start_object(&b, "1");
    bson_append_binary(&b, "id", sandbox_id, SANDBOX_ID_LEN);
    
    bson_append_string(&b, "hint", "permission");
    bson_append_start_object(&b, "opts");
    bson_append_string(&b, "op", op);
    bson_append_start_array(&b, "args");
    bson_append_binary(&b, "0", luid, WISH_UID_LEN);
    bson_append_element(&b, "1", &it);
    if (BSON_EOO != bson_find_from_buffer(&it, args, "4")) {
        /* We have friend request with metadata, add it to the actual friend request to be sent by core */
        bson_append_element(&b, "2", &it);
    }
    bson_append_finish_array(&b);
    bson_append_int(&b, "id", req->id);
    
    bson_append_finish_object(&b);
    
    bson_append_finish_object(&b);
    bson_append_finish_array(&b);
    bson_finish(&b);

    rpc_server_emit_broadcast(mist_api->server, "signals", bson_data(&b), bson_size(&b));
}

void sandbox_identity_remove(rpc_server_req* req, const uint8_t* args) {
    mist_api_t* mist_api = (mist_api_t*) req->server->context;
    //WISHDEBUG(LOG_CRITICAL, "sandbox_identity_remove");

    const char* op = "identity.remove";

    sandbox_t* sandbox = sandbox_from_args(req, args);

    if (sandbox == NULL) { return; }

    bson_iterator it;

    if (BSON_BINDATA != bson_find_from_buffer(&it, args, "2")) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }

    if (WISH_UID_LEN != bson_iterator_bin_len(&it)) {
        rpc_server_error_msg(req, 60, "Invalid uid.");
        return;
    }

    const char* uid = bson_iterator_bin_data(&it);

    if (!mist_sandbox_uid_in_peers(mist_api, sandbox, uid)) {
        rpc_server_error_msg(req, 60, "Identity not in sandbox.");
        return;
    }

    bson_type t = bson_find_from_buffer(&it, args, "1");

    if ( !(t == BSON_NULL || t == BSON_OBJECT) ) {
        rpc_server_error_msg(req, 58, "Core id not null or Peer/Connection.");
        return;
    }

    if ( t == BSON_NULL ) {
        sandbox_wish_request(req, op, args);
        
        // requested to remove peer from local wish core, we should also remove 
        // all peers from all sandboxes that have this identity as a ruid
        mist_sandbox_remove_peers_by_uid(mist_api, uid);
        
        return;
    }

    if (t == BSON_OBJECT) {
        sandbox_wish_connections_request(req, op, args);
        return;
    }
}
