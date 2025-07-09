#ifndef SERVER_UTIL_H
#define SERVER_UTIL_H

#include <stdlib.h>

void generate_random_string(char *buffer, int length);
char* sanitize_html(const char *input);

#endif
