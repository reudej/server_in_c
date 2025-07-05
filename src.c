#include <kore/kore.h>
#include <kore/http.h>
#include <kore/pgsql.h>
#include <postgresql/libpq-fe.h>
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
static PGconn *pg_conn = NULL;

// =============================================================================
// UTILITY FUNKCE
// =============================================================================

void generate_random_string(char *buffer, int length) {
    unsigned char random_bytes[length / 2];
    RAND_bytes(random_bytes, length / 2);
    for (int i = 0; i < length / 2; i++) {
        sprintf(buffer + (i * 2), "%02x", random_bytes[i]);
    }
    buffer[length] = '\0';
}

char* sanitize_html(const char *input) {
    if (!input) return NULL;
    int len = strlen(input);
    char *output = malloc(len * 6 + 1);
    int out_pos = 0;
    for (int i = 0; i < len; i++) {
        switch (input[i]) {
            case '<': strcpy(output + out_pos, "&lt;"); out_pos += 4; break;
            case '>': strcpy(output + out_pos, "&gt;"); out_pos += 4; break;
            case '&': strcpy(output + out_pos, "&amp;"); out_pos += 5; break;
            case '"': strcpy(output + out_pos, "&quot;"); out_pos += 6; break;
            case '\'': strcpy(output + out_pos, "&#x27;"); out_pos += 6; break;
            default: output[out_pos++] = input[i]; break;
        }
    }
    output[out_pos] = '\0';
    return output;
}

// =============================================================================
// DATABÁZE POSTGRESQL
// =============================================================================

static struct kore_pgsql sql;

void db_connect_async(struct http_request *req) {
    if (!kore_pgsql_setup(&sql, req, "host=localhost dbname=webapp user=webuser password=secret")) {
        kore_log(LOG_ERR, "pgsql_setup failed");
        http_response(req, 500, "Database error", 14);
    }
}

int db_insert_user(const char *name, const char *email) {
    char query[1024];
    snprintf(query, sizeof(query),
             "INSERT INTO users (name, email) VALUES ('%s', '%s')",
             name, email);
    return kore_pgsql_query(&sql, query);
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

int init_database(const char *conninfo) {
    pg_conn = PQconnectdb(conninfo);
    if (PQstatus(pg_conn) != CONNECTION_OK) {
        kore_log(LOG_ERR, "PostgreSQL připojení selhalo: %s", PQerrorMessage(pg_conn));
        PQfinish(pg_conn);
        return 0;
    }
    return 1;
}

int create_table(const char *query) {
    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        kore_log(LOG_ERR, "Chyba při vytváření tabulky: %s", PQerrorMessage(pg_conn));
        PQclear(res);
        return 0;
    }
    PQclear(res);
    return 1;
}

int model_insert(const char *table, const char **fields, const char **values, int count) {
    char fields_buf[1024] = "";
    char values_buf[1024] = "";

    for (int i = 0; i < count; i++) {
        strcat(fields_buf, fields[i]);
        strcat(values_buf, "'");
        strcat(values_buf, values[i]);
        strcat(values_buf, "'");
        if (i < count - 1) {
            strcat(fields_buf, ", ");
            strcat(values_buf, ", ");
        }
    }

    char query[2048];
    snprintf(query, sizeof(query), "INSERT INTO %s (%s) VALUES (%s);", table, fields_buf, values_buf);

    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        kore_log(LOG_ERR, "Insert selhal: %s", PQerrorMessage(pg_conn));
        PQclear(res);
        return 0;
    }
    PQclear(res);
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

db_result_t* model_select(const char *table, const char *where_clause) {
    char query[MAX_QUERY_SIZE];
    if (where_clause) {
        snprintf(query, sizeof(query), "SELECT * FROM %s WHERE %s", table, where_clause);
    } else {
        snprintf(query, sizeof(query), "SELECT * FROM %s", table);
    }

    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        kore_log(LOG_ERR, "Dotaz selhal: %s", PQerrorMessage(pg_conn));
        PQclear(res);
        return NULL;
    }

    db_result_t *result = malloc(sizeof(db_result_t));
    result->record_count = PQntuples(res);
    result->field_count = PQnfields(res);

    result->field_names = malloc(sizeof(char*) * result->field_count);
    for (int i = 0; i < result->field_count; i++) {
        result->field_names[i] = strdup(PQfname(res, i));
    }

    db_record_t *last_record = NULL;
    result->records = NULL;

    for (int r = 0; r < result->record_count; r++) {
        db_record_t *record = malloc(sizeof(db_record_t));
        record->field_count = result->field_count;
        record->values = malloc(sizeof(char*) * record->field_count);
        record->next = NULL;

        for (int f = 0; f < result->field_count; f++) {
            char *val = PQgetvalue(res, r, f);
            record->values[f] = strdup(val ? val : "");
        }

        if (last_record) {
            last_record->next = record;
        } else {
            result->records = record;
        }
        last_record = record;
    }

    PQclear(res);
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
