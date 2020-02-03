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
#include <string.h>
#include "mist_api.h"
#include "mist_api_persistence.h"
#include "wish_debug.h"
#include "bson.h"
#include "wish_fs.h"
#include "utlist.h"

#define MIST_API_PEERS_DB_FILE "mist_api_peers_db.bin"

static void mist_api_write_file(const char* buf, int buf_len) {
    wish_fs_remove(MIST_API_PEERS_DB_FILE);
    wish_file_t fd = wish_fs_open(MIST_API_PEERS_DB_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Mist api peers db could not be saved.");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    int32_t len = wish_fs_write(fd, buf, buf_len);
    WISHDEBUG(LOG_CRITICAL, "mist_api_write_file: Wrote %i bytes", len);
    wish_fs_close(fd);
}

void mist_api_peers_db_save(mist_api_t *mist_api) {
        //WISHDEBUG(LOG_CRITICAL, "Saving sandbox states:");
    if (mist_api->wish_app == NULL) {
        WISHDEBUG(LOG_CRITICAL, "Error: Cannot satisfy request because mist_api->wish_app is NULL");
        return;
    }

    bson bs;
    bson_init(&bs);
    bson_append_start_array(&bs, "data");

    int i = 0;
    peers_list *elem = NULL;
    
    LL_FOREACH(mist_api->peers_db, elem) {
        char i_str[21] = { 0 };
        BSON_NUMSTR(i_str, i);
        bson_append_start_object(&bs, i_str);
        bson_append_binary(&bs, "luid", elem->peer.luid, WISH_UID_LEN);
        bson_append_binary(&bs, "ruid", elem->peer.ruid, WISH_UID_LEN);
        bson_append_binary(&bs, "rhid", elem->peer.rhid, WISH_UID_LEN);
        bson_append_binary(&bs, "rsid", elem->peer.rsid, WISH_UID_LEN);
        bson_append_string_maxlen(&bs, "protocol", elem->peer.protocol, WISH_PROTOCOL_NAME_MAX_LEN);
        bson_append_finish_object(&bs);
        i++;
    }
    
    bson_append_finish_array(&bs);
    bson_finish(&bs);
    
    //WISHDEBUG(LOG_CRITICAL, "  about write sandbox file:");
    //bson_visit((char*)bson_data(&bs), elem_visitor);
    
    mist_api_write_file( bson_data(&bs), bson_size(&bs) );
    bson_destroy(&bs);

}

void mist_api_peers_db_load(mist_api_t *mist_api) {
    wish_file_t fd = wish_fs_open(MIST_API_PEERS_DB_FILE);
    if (fd <= 0) {
        WISHDEBUG(LOG_CRITICAL, "Error opening file! Mist api peers db could not be loaded!");
        return;
    }
    wish_fs_lseek(fd, 0, WISH_FS_SEEK_SET);
    
    
    int size = 0;
    

    int read_ret = wish_fs_read(fd, (void*) &size, 4);

    if (read_ret != 4) {
        //WISHDEBUG(LOG_CRITICAL, "Empty file, or read error in mist api peers db load.");
        return;
    }

    if(size>64*1024) {
        WISHDEBUG(LOG_CRITICAL, "Mist api peers db load, file too large (64KiB limit). Found: %i bytes.", size);
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
    
    /* Load content from sandbox file */
    
    bson_iterator it;
    bson_iterator pit;
    bson_iterator poit;
    
    if ( bson_find(&it, &bs, "data") != BSON_ARRAY ) {
        // that didn't work
        WISHDEBUG(LOG_CRITICAL, "No data element when reviving mist api peers db");
        bson_destroy(&bs);
        return;
    }
    
    int i = 0;
    
    while (true) {
        char sindex[21] = { 0 };
        BSON_NUMSTR(sindex, i++);
        
        bson_iterator_subiterator(&it, &pit);
        if ( bson_find_fieldpath_value(sindex, &pit) != BSON_OBJECT ) {
            // that didn't work
            WISHDEBUG(LOG_CRITICAL, "Not an object at index %s when reviving mist api peers db", sindex);
            bson_destroy(&bs);
            return;
        }
        
        bson_iterator_subiterator(&pit, &poit);
        if ( bson_find_fieldpath_value("luid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
            WISHDEBUG(LOG_CRITICAL, "That didn't work luid, when reviving mist api peers db."); 
            break; 
        }
        const char* luid = bson_iterator_bin_data(&poit);

        bson_iterator_subiterator(&pit, &poit);
        if ( bson_find_fieldpath_value("ruid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
            WISHDEBUG(LOG_CRITICAL, "That didn't work ruid, when reviving mist api peers db."); break; }
        const char* ruid = bson_iterator_bin_data(&poit);

        bson_iterator_subiterator(&pit, &poit);
        if ( bson_find_fieldpath_value("rhid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
            WISHDEBUG(LOG_CRITICAL, "That didn't work rhid, when reviving mist api peers db."); break; }
        const char* rhid = bson_iterator_bin_data(&poit);

        bson_iterator_subiterator(&pit, &poit);
        if ( bson_find_fieldpath_value("rsid", &poit) != BSON_BINDATA || bson_iterator_bin_len(&poit) != WISH_UID_LEN ) { 
            WISHDEBUG(LOG_CRITICAL, "That didn't work rsid, when reviving mist api peers db."); break; }
        const char* rsid = bson_iterator_bin_data(&poit);

        bson_iterator_subiterator(&pit, &poit);
        if ( bson_find_fieldpath_value("protocol", &poit) != BSON_STRING || bson_iterator_string_len(&poit) > WISH_PROTOCOL_NAME_MAX_LEN ) { 
            WISHDEBUG(LOG_CRITICAL, "That didn't work protocol, when reviving mist api peers db."); break; }
        const char* protocol = bson_iterator_string(&poit);

        //WISHDEBUG(LOG_CRITICAL, "Got all the way here. %s", protocol);

        peers_list* pe = wish_platform_malloc(sizeof(peers_list));
        if (pe == NULL) { WISHDEBUG(LOG_CRITICAL, "Memory full! Allocating %i, when reviving mist-api peer list", sizeof(peers_list)); return; }
        
        memcpy(&pe->peer.luid, luid, WISH_UID_LEN);
        memcpy(&pe->peer.ruid, ruid, WISH_UID_LEN);
        memcpy(&pe->peer.rhid, rhid, WISH_UID_LEN);
        memcpy(&pe->peer.rsid, rsid, WISH_UID_LEN);
        strncpy(pe->peer.protocol, protocol, WISH_PROTOCOL_NAME_MAX_LEN);
        pe->peer.online = false;
        LL_APPEND(mist_api->peers_db, pe);

    }    
    bson_destroy(&bs);

}