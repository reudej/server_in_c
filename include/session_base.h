#ifndef SESSION_ID_SIZE
#include <time.h>

#define MAX_SESSIONS 1000
#define CSRF_TOKEN_SIZE 32
#define SESSION_ID_SIZE 16

static session_t sessions[MAX_SESSIONS];
static int session_count = 0;

// Struktura pro CSRF token
typedef struct {
    char token[CSRF_TOKEN_SIZE * 2 + 1];
    time_t created;
    int used;
} csrf_token_t;


// Struktura pro session
typedef struct {
    char session_id[SESSION_ID_SIZE * 2 + 1];
    csrf_token_t csrf;
    time_t last_access;
    char *user_data;
} session_t;
#endif
