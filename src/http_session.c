#include <kore/kore.h>
#include "session_base.h"

// Najití session podle ID
session_t* find_session(const char *session_id) {
    for (int i = 0; i < session_count; i++) {
        if (strcmp(sessions[i].session_id, session_id) == 0) {
            return &sessions[i];
        }
    }
    return NULL;
}

// Získání session z HTTP požadavku
session_t* get_session_from_request(struct http_request *req) {
    char *session_cookie;
    if (http_request_cookie(req, "sessionid", &session_cookie) == KORE_RESULT_OK) {
        return find_session(session_cookie);
    }
    return NULL;
}

// Nastavení session cookie
void set_session_cookie(struct http_request *req, session_t *session) {
    http_response_cookie(req, "sessionid", session->session_id, "/", 0, 0, NULL);
}