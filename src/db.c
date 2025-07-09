#include <kore/kore.h>
#include <postgresql/libpq-fe.h>

#define MAX_IDENTIFIER_LEN 63
#define MAX_QUERY_SIZE 4096

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

static PGconn *pg_conn = NULL;
static struct kore_pgsql sql;

void db_connect_async(struct http_request *req) {
    if (!kore_pgsql_setup(&sql, req, "host=localhost dbname=webapp user=webuser password=secret")) {
        kore_log(LOG_ERR, "pgsql_setup failed");
        http_response(req, 500, "Database error", 14);
    }
}

char* sanitize_sql_value(const char *input, const int single_or_double_quote) {
    if (!input) return strdup("");

    size_t len = strlen(input);
    // Nejhorší případ: každý znak je uvozovka a je zdvojena => 2× velikost + 1
    char *sanitized = malloc(len * 2 + 1);
    if (!sanitized) return NULL;

    char quote;
    if (single_or_double_quote) quote = '\'';
    else quote = '"'; 
    char *dst = sanitized;
    for (const char *src = input; *src; src++) {
        if (*src == quote) {
            *dst++ = quote;
            *dst++ = quote;
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    return sanitized;
}

int validate_where_clause(const char *where_clause) {
    if (!where_clause) return 0;

    for (int i = 0; where_clause[i] != '\0'; i++) {
        char c = where_clause[i];

        if (isalnum((unsigned char)c) || c == '_' || c == ' ' || c == '\t' ||
            c == '=' || c == '<' || c == '>' || c == '!' ||
            c == '(' || c == ')' || c == ',' || c == '\'' || c == '.' ||
            c == '%' || c == '_' || c == '-' ) {
            // povolený znak
            continue;
        }

        // nepovolený znak
        return 0;
    }

    return 1;
}

int is_valid_sql_id(const char *s) {
    if (!s || strlen(s) == 0 || strlen(s) > MAX_IDENTIFIER_LEN)
        return 0;

    if (!isalpha(s[0]) && s[0] != '_')
        return 0;

    for (int i = 1; s[i] != '\0'; i++) {
        if (!isalnum(s[i]) && s[i] != '_')
            return 0;
    }

    return 1;
}

signed int validate_sql_ids(char **identifiers, int count) {
    for (int i=0;i < count;i++) {
        if (!is_valid_sql_id(identifiers[i])) {
            return i;  // nevalidní název na indexu i
        }
    }
    return -1;  // vše OK
}

int init_database(const char *conninfo) {
    pg_conn = PQconnectdb(conninfo);
    if (PQstatus(pg_conn) != CONNECTION_OK) {
        kore_log(LOG_ERR, "PostgreSQL connnection failed: %s", PQerrorMessage(pg_conn));
        PQfinish(pg_conn);
        return 0;
    }
    return 1;
}

int sql_query_exc(const char *query) {
    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        kore_log(LOG_ERR, "Error while executing command: %s", PQerrorMessage(pg_conn));
        PQclear(res);
        return 0;
    }
    PQclear(res);
    return 1;
}

int sql_insert(const char *table, const char **fields, const char **values, int count) {
    if (count <= 0) return 0;

    int invalid_id_i = validate_sql_ids(fields, count);
    if (invalid_id_i != -1) {
        kore_log(LOG_ERR, "SQL insert failed: invalid field id on index %d: %s", invalid_id_i, fields[invalid_id_i]);
        return 0;
    }

    char fields_buf[1024] = "";
    for (int i = 0; i < count; i++) {
        strcat(fields_buf, fields[i]);
        if (i < count - 1) {
            strcat(fields_buf, ", ");
        }
    }

    // Vytvoříme parametrizovaný dotaz s $1, $2, ... dle počtu polí
    char query[2048] = "";
    snprintf(query, sizeof(query), "INSERT INTO %s (%s) VALUES (", table, fields_buf);

    for (int i = 0; i < count; i++) {
        char param[8];
        snprintf(param, sizeof(param), "$%d", i + 1);
        strcat(query, param);
        if (i < count - 1) {
            strcat(query, ", ");
        }
    }
    strcat(query, ");");

    // Pole hodnot pro parametry
    const char *paramValues[count];
    for (int i = 0; i < count; i++) {
        paramValues[i] = values[i];
    }

    // Spustíme parametrizovaný dotaz
    PGresult *res = PQexecParams(pg_conn,
                                 query,
                                 count,       // počet parametrů
                                 NULL,        // typy (NULL = nechá to na serveru)
                                 paramValues, // hodnoty parametrů
                                 NULL,        // délky parametrů (NULL znamená textové)
                                 NULL,        // formát parametrů (NULL = text)
                                 0);          // formát výsledku (0 = text)

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        kore_log(LOG_ERR, "SQL insert failed: %s", PQerrorMessage(pg_conn));
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

db_result_t* sql_select(const char *table, const char *where_clause) {
    if (!is_valid_sql_id(table)) {
        kore_log(LOG_ERR, "SQL select failed: invalid table id: %s", table);
        return NULL;
    }

    char query[MAX_QUERY_SIZE];
    if (where_clause) {
        if (validate_where_clause(where_clause)) snprintf(query, sizeof(query), "SELECT * FROM %s WHERE %s", table, where_clause);
        else {
            kore_log(LOG_ERR, "SQL select failed: invalid or unsupported where claause: %s", where_clause);
            return NULL;
        }
    } else {
        snprintf(query, sizeof(query), "SELECT * FROM %s", table);
    }

    PGresult *res = PQexec(pg_conn, query);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        kore_log(LOG_ERR, "SQL select failed: %s", PQerrorMessage(pg_conn));
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
