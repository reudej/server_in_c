#ifndef SESSION_HTTP_H
#define SESSION_HTTP_H

#include <kore/kore.h>
#include "session_base.h"

session_t* find_session(const char *session_id);
session_t* get_session_from_request(struct http_request *req);
void set_session_cookie(struct http_request *req, session_t *session);

#endif
