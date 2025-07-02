#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// =============================================================================
// ZÁKLADNÍ STRUKTURY A DEFINICE
// =============================================================================

#define MAX_TEMPLATE_SIZE 65536
#define MAX_QUERY_SIZE 4096
#define MAX_SESSIONS 1000
#define CSRF_TOKEN_SIZE 32
#define SESSION_ID_SIZE 16

// Struktura pro šablonový systém
typedef struct {
    char *name;
    char *content;
    char *parent;
    struct template_t *next;
} template_t;

// Struktura pro kontext šablony
typedef struct {
    char **keys;
    char **values;
    int count;
    int capacity;
} template_context_t;

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

// Struktura pro databázové modely
typedef struct {
    char *table_name;
    char **fields;
    char **field_types;
    int field_count;
} db_model_t;

// Struktura pro databázové záznamy
typedef struct {
    char **values;
    int field_count;
    struct db_record_t *next;
} db_record_t;

// Struktura pro databázový výsledek
typedef struct {
    db_record_t *records;
    int record_count;
    char **field_names;
    int field_count;
} db_result_t;

// =============================================================================
// GLOBÁLNÍ PROMĚNNÉ
// =============================================================================

static template_t *templates = NULL;
static session_t sessions[MAX_SESSIONS];
static int session_count = 0;
static sqlite3 *db = NULL;

// =============================================================================
// UTILITY FUNKCE
// =============================================================================

// Generování náhodných řetězců pro tokeny
void generate_random_string(char *buffer, int length) {
    unsigned char random_bytes[length / 2];
    RAND_bytes(random_bytes, length / 2);
    
    for (int i = 0; i < length / 2; i++) {
        sprintf(buffer + (i * 2), "%02x", random_bytes[i]);
    }
    buffer[length] = '\0';
}

// Sanitizace HTML
char* sanitize_html(const char *input) {
    if (!input) return NULL;
    
    int len = strlen(input);
    char *output = malloc(len * 6 + 1); // Nejhorší případ: každý znak se nahradí entitou
    int out_pos = 0;
    
    for (int i = 0; i < len; i++) {
        switch (input[i]) {
            case '<':
                strcpy(output + out_pos, "&lt;");
                out_pos += 4;
                break;
            case '>':
                strcpy(output + out_pos, "&gt;");
                out_pos += 4;
                break;
            case '&':
                strcpy(output + out_pos, "&amp;");
                out_pos += 5;
                break;
            case '"':
                strcpy(output + out_pos, "&quot;");
                out_pos += 6;
                break;
            case '\'':
                strcpy(output + out_pos, "&#x27;");
                out_pos += 6;
                break;
            default:
                output[out_pos++] = input[i];
                break;
        }
    }
    output[out_pos] = '\0';
    return output;
}

// =============================================================================
// ŠABLONOVÝ SYSTÉM
// =============================================================================

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

// =============================================================================
// SESSION A CSRF SYSTÉM
// =============================================================================

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

// =============================================================================
// DATABÁZOVÝ SYSTÉM
// =============================================================================

// Inicializace databáze
int init_database(const char *db_path) {
    int rc = sqlite3_open(db_path, &db);
    if (rc) {
        kore_log(LOG_ERR, "Nelze otevřít databázi: %s", sqlite3_errmsg(db));
        return 0;
    }
    return 1;
}

// Vytvoření databázového modelu
db_model_t* create_model(const char *table_name) {
    db_model_t *model = malloc(sizeof(db_model_t));
    model->table_name = strdup(table_name);
    model->fields = NULL;
    model->field_types = NULL;
    model->field_count = 0;
    return model;
}

// Přidání pole do modelu
void model_add_field(db_model_t *model, const char *field_name, const char *field_type) {
    model->field_count++;
    model->fields = realloc(model->fields, sizeof(char*) * model->field_count);
    model->field_types = realloc(model->field_types, sizeof(char*) * model->field_count);
    
    model->fields[model->field_count - 1] = strdup(field_name);
    model->field_types[model->field_count - 1] = strdup(field_type);
}

// Vytvoření tabulky v databázi
int create_table(db_model_t *model) {
    char query[MAX_QUERY_SIZE];
    snprintf(query, sizeof(query), "CREATE TABLE IF NOT EXISTS %s (id INTEGER PRIMARY KEY AUTOINCREMENT", 
             model->table_name);
    
    for (int i = 0; i < model->field_count; i++) {
        char field_def[256];
        snprintf(field_def, sizeof(field_def), ", %s %s", 
                 model->fields[i], model->field_types[i]);
        strcat(query, field_def);
    }
    strcat(query, ")");
    
    char *err_msg = 0;
    int rc = sqlite3_exec(db, query, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        kore_log(LOG_ERR, "SQL error: %s", err_msg);
        sqlite3_free(err_msg);
        return 0;
    }
    
    return 1;
}

// Vložení záznamu do databáze
int model_insert(db_model_t *model, char **values) {
    char query[MAX_QUERY_SIZE];
    char fields_str[512] = "";
    char values_str[512] = "";
    
    for (int i = 0; i < model->field_count; i++) {
        if (i > 0) {
            strcat(fields_str, ", ");
            strcat(values_str, ", ");
        }
        strcat(fields_str, model->fields[i]);
        strcat(values_str, "?");
    }
    
    snprintf(query, sizeof(query), "INSERT INTO %s (%s) VALUES (%s)", 
             model->table_name, fields_str, values_str);
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        kore_log(LOG_ERR, "Prepare failed: %s", sqlite3_errmsg(db));
        return 0;
    }
    
    for (int i = 0; i < model->field_count; i++) {
        sqlite3_bind_text(stmt, i + 1, values[i], -1, SQLITE_STATIC);
    }
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    return (rc == SQLITE_DONE) ? 1 : 0;
}

// Dotaz na databázi
db_result_t* model_select(db_model_t *model, const char *where_clause) {
    char query[MAX_QUERY_SIZE];
    if (where_clause) {
        snprintf(query, sizeof(query), "SELECT * FROM %s WHERE %s", 
                 model->table_name, where_clause);
    } else {
        snprintf(query, sizeof(query), "SELECT * FROM %s", model->table_name);
    }
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    
    if (rc != SQLITE_OK) {
        kore_log(LOG_ERR, "Prepare failed: %s", sqlite3_errmsg(db));
        return NULL;
    }
    
    db_result_t *result = malloc(sizeof(db_result_t));
    result->records = NULL;
    result->record_count = 0;
    result->field_count = sqlite3_column_count(stmt);
    
    // Získat názvy sloupců
    result->field_names = malloc(sizeof(char*) * result->field_count);
    for (int i = 0; i < result->field_count; i++) {
        result->field_names[i] = strdup(sqlite3_column_name(stmt, i));
    }
    
    // Načíst záznamy
    db_record_t *last_record = NULL;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        db_record_t *record = malloc(sizeof(db_record_t));
        record->field_count = result->field_count;
        record->values = malloc(sizeof(char*) * record->field_count);
        record->next = NULL;
        
        for (int i = 0; i < record->field_count; i++) {
            const char *value = (const char*)sqlite3_column_text(stmt, i);
            record->values[i] = value ? strdup(value) : strdup("");
        }
        
        if (last_record) {
            last_record->next = record;
        } else {
            result->records = record;
        }
        last_record = record;
        result->record_count++;
    }
    
    sqlite3_finalize(stmt);
    return result;
}

// =============================================================================
// HTTP HANDLERY
// =============================================================================

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

// Hlavní handler pro domovskou stránku
int home_handler(struct http_request *req) {
    session_t *session = get_session_from_request(req);
    if (!session) {
        session = create_session();
        if (session) {
            set_session_cookie(req, session);
        }
    }
    
    template_context_t *ctx = create_template_context();
    context_add(ctx, "title", "Domovská stránka");
    context_add(ctx, "message", "Vítejte v C Web Frameworku!");
    
    if (session) {
        context_add(ctx, "csrf_token", session->csrf.token);
    }
    
    char *rendered = render_template("home", ctx);
    
    if (rendered) {
        http_response(req, 200, rendered, strlen(rendered));
        free(rendered);
    } else {
        http_response(req, 500, "Template not found", 18);
    }
    
    return KORE_RESULT_OK;
}

// Handler pro formuláře s CSRF ochranou
int form_handler(struct http_request *req) {
    if (req->method == HTTP_METHOD_POST) {
        session_t *session = get_session_from_request(req);
        if (!session) {
            http_response(req, 403, "No session", 10);
            return KORE_RESULT_OK;
        }
        
        char *csrf_token;
        if (http_argument_get_string(req, "csrf_token", &csrf_token) != KORE_RESULT_OK) {
            http_response(req, 403, "Missing CSRF token", 18);
            return KORE_RESULT_OK;
        }
        
        if (!validate_csrf_token(session, csrf_token)) {
            http_response(req, 403, "Invalid CSRF token", 18);
            return KORE_RESULT_OK;
        }
        
        // Zpracovat formulář
        char *name, *email;
        if (http_argument_get_string(req, "name", &name) == KORE_RESULT_OK &&
            http_argument_get_string(req, "email", &email) == KORE_RESULT_OK) {
            
            // Sanitizace
            char *safe_name = sanitize_html(name);
            char *safe_email = sanitize_html(email);
            
            // Uložit do databáze (příklad)
            db_model_t *user_model = create_model("users");
            model_add_field(user_model, "name", "TEXT");
            model_add_field(user_model, "email", "TEXT");
            
            char *values[] = {safe_name, safe_email};
            model_insert(user_model, values);
            
            free(safe_name);
            free(safe_email);
            
            http_response(req, 200, "Form submitted successfully", 24);
        } else {
            http_response(req, 400, "Missing form data", 17);
        }
    } else {
        // Zobrazit formulář
        session_t *session = get_session_from_request(req);
        if (!session) {
            session = create_session();
            set_session_cookie(req, session);
        }
        
        template_context_t *ctx = create_template_context();
        context_add(ctx, "title", "Formulář");
        context_add(ctx, "csrf_token", session->csrf.token);
        
        char *rendered = render_template("form", ctx);
        
        if (rendered) {
            http_response(req, 200, rendered, strlen(rendered));
            free(rendered);
        } else {
            http_response(req, 500, "Template not found", 18);
        }
    }
    
    return KORE_RESULT_OK;
}

// =============================================================================
// EXPORTOVANÉ FUNKCE PRO KORE.IO
// =============================================================================

int page_handler(struct http_request *req) {
    return home_handler(req);
}

int form_page_handler(struct http_request *req) {
    return form_handler(req);
}