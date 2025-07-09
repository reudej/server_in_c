#include <stdio.h>

extern template_t *templates = NULL;

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

// Registrace šablony
void register_template(const char *name, const char *content, const char *parent) {
    template_t *tmpl = malloc(sizeof(template_t));
    tmpl->name = strdup(name);
    tmpl->content = strdup(content);
    tmpl->parent = parent ? strdup(parent) : NULL;
    tmpl->next = templates;
    templates = tmpl;
}

// Najití šablony podle názvu
template_t* find_template(const char *name) {
    template_t *current = templates;
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Vytvoření kontextu šablony
template_context_t* create_template_context() {
    template_context_t *ctx = malloc(sizeof(template_context_t));
    ctx->capacity = 10;
    ctx->count = 0;
    ctx->keys = malloc(sizeof(char*) * ctx->capacity);
    ctx->values = malloc(sizeof(char*) * ctx->capacity);
    return ctx;
}

// Přidání klíče a hodnoty do kontextu
void context_add(template_context_t *ctx, const char *key, const char *value) {
    if (ctx->count >= ctx->capacity) {
        ctx->capacity *= 2;
        ctx->keys = realloc(ctx->keys, sizeof(char*) * ctx->capacity);
        ctx->values = realloc(ctx->values, sizeof(char*) * ctx->capacity);
    }
    
    ctx->keys[ctx->count] = strdup(key);
    ctx->values[ctx->count] = strdup(value);
    ctx->count++;
}

// Nahrazení proměnných v šabloně
char* replace_variables(const char *template, template_context_t *ctx) {
    char *result = strdup(template);
    
    for (int i = 0; i < ctx->count; i++) {
        char variable[256];
        snprintf(variable, sizeof(variable), "{{ %s }}", ctx->keys[i]);
        
        char *pos = strstr(result, variable);
        while (pos) {
            int var_len = strlen(variable);
            int val_len = strlen(ctx->values[i]);
            int result_len = strlen(result);
            
            char *new_result = malloc(result_len - var_len + val_len + 1);
            
            // Kopírovat část před proměnnou
            int prefix_len = pos - result;
            strncpy(new_result, result, prefix_len);
            
            // Kopírovat hodnotu
            strcpy(new_result + prefix_len, ctx->values[i]);
            
            // Kopírovat zbytek
            strcpy(new_result + prefix_len + val_len, pos + var_len);
            
            free(result);
            result = new_result;
            
            pos = strstr(result, variable);
        }
    }
    
    return result;
}

// Renderování šablony s dědičností
char* render_template(const char *name, template_context_t *ctx) {
    template_t *tmpl = find_template(name);
    if (!tmpl) return NULL;
    
    char *content = replace_variables(tmpl->content, ctx);
    
    // Pokud má šablona rodiče, zpracovat dědičnost
    if (tmpl->parent) {
        template_t *parent = find_template(tmpl->parent);
        if (parent) {
            // Najít {% block %} značky v rodičovské šabloně
            char *parent_content = strdup(parent->content);
            
            // Jednoduchá implementace bloků - nahradit {% block content %} obsahem
            char *block_start = strstr(parent_content, "{% block content %}");
            if (block_start) {
                char *block_end = strstr(block_start, "{% endblock %}");
                if (block_end) {
                    int prefix_len = block_start - parent_content;
                    int suffix_start = block_end - parent_content + strlen("{% endblock %}");
                    
                    char *result = malloc(strlen(parent_content) + strlen(content) + 1);
                    strncpy(result, parent_content, prefix_len);
                    result[prefix_len] = '\0';
                    strcat(result, content);
                    strcat(result, parent_content + suffix_start);
                    
                    free(parent_content);
                    free(content);
                    content = replace_variables(result, ctx);
                    free(result);
                }
            }
        }
    }
    
    return content;
}
