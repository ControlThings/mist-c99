#include "wish_protocol.h"

int bson_append_peer(bson *b, const char *name_or_null, const wish_protocol_peer_t* peer) {
    if (name_or_null != NULL) { bson_append_start_object(b, name_or_null); }
    
    bson_append_binary(b, "luid", (char*) peer->luid, WISH_UID_LEN);
    bson_append_binary(b, "ruid", (char*) peer->ruid, WISH_UID_LEN);
    bson_append_binary(b, "rhid", (char*) peer->rhid, WISH_UID_LEN);
    bson_append_binary(b, "rsid", (char*) peer->rsid, WISH_UID_LEN);
    bson_append_string(b, "protocol", peer->protocol);
    bson_append_bool(b, "online", peer->online);
    
    if (name_or_null != NULL) { bson_append_finish_object(b); }
    
    return BSON_OK;
}
        
        