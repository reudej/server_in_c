#ifndef SERVER_TEMPLATE_H
#define SERVER_TEMPLATE_H

#include <stdio.h>

// Struktura pro kontext šablony
typedef struct {
    char **keys;
    char **values;
    int count;
    int capacity;
} template_context_t;

// Struktura pro šablonový systém
typedef struct {
    char *name;
    char *content;
    char *parent;
    struct template_t *next;
} template_t;

extern template_t *templates = NULL;

void register_template(const char *name, const char *content, const char *parent);
template_context_t* create_template_context();
void context_add(template_context_t *ctx, const char *key, const char *value);
char* replace_variables(const char *template, template_context_t *ctx);
char* render_template(const char *name, template_context_t *ctx);

#endif