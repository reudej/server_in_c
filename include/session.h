#ifndef MAX_SESSIONS

#include <time.h>
#include "session_base.h"

session_t* create_session(void);
int validate_csrf_token(session_t *session, const char *token);

#endif
