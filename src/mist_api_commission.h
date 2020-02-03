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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "wish_protocol.h"
    
enum commissioning_states {
    COMMISSION_STATE_INITIAL,
    COMMISSION_STATE_NO_CALLBACK_LISTENER,
    COMMISSION_STATE_WAIT_WLD_OR_WIFI_SELECT,
    COMMISSION_STATE_WAIT_JOIN_COMMISIONING_WIFI,
    COMMISSION_STATE_WAIT_WIFI_ENABLED,
    COMMISSION_STATE_WIFI_DISABLED,
    COMMISSION_STATE_WAIT_WLD_CLEAR,
    COMMISSION_STATE_WAIT_WLD_LIST,
    COMMISSION_STATE_WAIT_SELECT_LOCAL_ID,
    COMMISSION_STATE_WAIT_FRIEND_REQ_RESP,
    COMMISSION_STATE_WAIT_FOR_PEERS,
    COMMISSION_STATE_WAIT_FOR_CLAIM_USER_DECISION,
    COMMISSION_STATE_WAIT_MANAGE_CLAIM_CB,
    COMMISSION_STATE_WAIT_WIFI_CONFIG,
    COMMISSION_STATE_WAIT_JOIN_ORIGINAL_WIFI,
    COMMISSION_STATE_WAIT_COMMISSIONED_PEER_OFFLINE,
    COMMISSION_STATE_WAIT_COMMISSIONED_PEER_ONLINE,
    COMMISSION_STATE_FINISHED_OK,
    COMMISSION_STATE_FINISHED_FAIL,
    COMMISSION_STATE_ABORTED
};

typedef struct commissioning_s {
    enum commissioning_states state;
    int timer;
    int retry_timer;
    // Server unique request id
    int req_sid;
    bool is_wifi_commissioning;
    const char* original_ssid;
    char* sandbox_id;
    /** True, if commssioning is started from sandbox. In that case sandbox_id must be different from NULL. False when commissioning started directly via mist-api */
    bool via_sandbox;
    wish_protocol_peer_t peer;
    // device class (wld class tag)
    const char* wld_class;
    char* standalone_ssid;
    char* standalone_password;
} commissioning;

typedef enum wifi_join_e {
    WIFI_JOIN_OK                = 0,
    WIFI_JOIN_FAILED            = 1,
    WIFI_OFF                    = 2, /* The wifi hardware has been detected to be switched off */
    WIFI_JOIN_UNEXPECTED        = 3, /* An unexpected wifi join event has occured when we were joining */
} wifi_join;
    
#include "mist_api.h"

typedef struct mist_api_context mist_api_t;

/* Commission API */

/* Commission Internals */

void commission_init(commissioning* c11g);

void commission_periodic(mist_api_t* mist_api);

void commission_event_start_wifi(mist_api_t* mist_api, const char* luid, 
        const char* ssid, const char* password, const char* wld_class);

void commission_event_start_wld(mist_api_t* mist_api, const char* luid,
        const char* ruid, const char* rhid, const char* wld_class);

void commission_event_wifi_join_ok(mist_api_t* mist_api);

void commission_event_wifi_join_failed(mist_api_t* mist_api);

void commission_event_wld_candidate_found(mist_api_t* mist_api);

void commission_event_wld_candidate_already_claimed(mist_api_t* mist_api);

void commission_event_wld_signal(mist_api_t* mist_api);

void commission_event_friend_req_accepted_signal(mist_api_t* mist_api);

void commission_event_friend_req_declined_signal(mist_api_t* mist_api);

void commission_event_peers_signal(mist_api_t* mist_api);

void commission_event_select_wifi(mist_api_t* mist_api, const char* type, const char* ssid, const char* password);

const char* commission_state_to_string(enum commissioning_states state);

#ifdef __cplusplus
}
#endif
