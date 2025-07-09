#include <time.h>
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

// Vytvoření nové session
session_t* create_session() {
    if (session_count >= MAX_SESSIONS) return NULL;
    
    session_t *session = &sessions[session_count++];
    generate_random_string(session->session_id, SESSION_ID_SIZE * 2);
    generate_random_string(session->csrf.token, CSRF_TOKEN_SIZE * 2);
    session->csrf.created = time(NULL);
    session->csrf.used = 0;
    session->last_access = time(NULL);
    session->user_data = NULL;
    
    return session;
}

// Validace CSRF tokenu
int validate_csrf_token(session_t *session, const char *token) {
    if (!session || !token) return 0;
    
    time_t now = time(NULL);
    if (now - session->csrf.created > 3600) { // Token vyprší za hodinu
        return 0;
    }
    
    if (session->csrf.used) return 0; // Token už byl použit
    
    if (strcmp(session->csrf.token, token) == 0) {
        session->csrf.used = 1;
        return 1;
    }
    
    return 0;
}
