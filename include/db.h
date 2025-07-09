#ifndef MAX_IDENTIFIER_LEN
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

void db_connect_async(struct http_request *req);
char* sanitize_sql_value(const char *input, const int single_or_double_quote);
int validate_where_clause(const char *where_clause);
int is_valid_sql_id(const char *s);
signed int validate_sql_ids(char **identifiers, int count);
int init_database(const char *conninfo);
int sql_query_exc(const char *query);
int sql_insert(const char *table, const char **fields, const char **values, int count);
db_model_t* create_model(const char *table_name);
void model_add_field(db_model_t *model, const char *field_name, const char *field_type);
db_result_t* sql_select(const char *table, const char *where_clause);

#endif