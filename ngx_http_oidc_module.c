#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <openssl/rand.h>

/*
 * Provider Metadata Structure
 */
typedef struct {
    ngx_str_t authorization_endpoint;
    ngx_str_t token_endpoint;
    ngx_str_t jwks_uri;
} ngx_http_oidc_provider_metadata_t;

/*
 * Module Configuration Structure
 *
 * auth_oidc は ngx_flag_t (on/off) に変更。
 * cached_metadata はワーカープロセスレベルでメタデータをキャッシュするための
 * ポインタ。設定後はリクエストをまたいで再利用される。
 */
typedef struct {
    ngx_flag_t   auth_oidc;
    ngx_str_t    oidc_provider;
    ngx_str_t    client_id;
    ngx_str_t    client_secret;
    ngx_str_t    redirect_uri;
    ngx_http_oidc_provider_metadata_t *cached_metadata;  /* worker-level cache */
} ngx_http_oidc_loc_conf_t;

/*
 * Request Context Structure
 *
 * metadata フィールドを廃止し、conf->cached_metadata に一本化した。
 */
typedef struct {
    ngx_uint_t discovery_attempted:1;
    ngx_uint_t token_attempted:1;
} ngx_http_oidc_ctx_t;

/* Forward declarations */
extern ngx_module_t ngx_http_oidc_module;

static ngx_int_t ngx_http_oidc_parse_discovery_json(
    ngx_http_request_t *r, ngx_pool_t *pool,
    const u_char *data, size_t len,
    ngx_http_oidc_provider_metadata_t *metadata);

/* ---------------------------------------------------------------------------
 * Helper: 指定バイト数の暗号論的乱数を 16 進文字列として生成する
 * Issue 1 対応: state/nonce を RAND_bytes で生成するために使用。
 * --------------------------------------------------------------------------- */
static ngx_int_t
ngx_http_oidc_generate_random_hex(ngx_pool_t *pool, ngx_uint_t bytes,
    ngx_str_t *out)
{
    u_char                   raw[32];
    u_char                  *p;
    ngx_uint_t               i;
    static const u_char      hex[] = "0123456789abcdef";

    if (bytes > sizeof(raw)) {
        bytes = sizeof(raw);
    }

    if (RAND_bytes(raw, (int) bytes) != 1) {
        return NGX_ERROR;
    }

    out->len  = bytes * 2;
    out->data = ngx_palloc(pool, out->len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = out->data;
    for (i = 0; i < bytes; i++) {
        *p++ = hex[raw[i] >> 4];
        *p++ = hex[raw[i] & 0x0f];
    }
    *p = '\0';

    return NGX_OK;
}

/* ---------------------------------------------------------------------------
 * Helper: redirect_uri からパス部分のみを抽出する
 * Issue 5 対応: フル URL（http://example.com/callback）が設定された場合に
 * r->uri（パスのみ）との比較が常に不一致になる問題を修正。
 * --------------------------------------------------------------------------- */
static void
ngx_http_oidc_extract_path(const ngx_str_t *uri, ngx_str_t *path)
{
    u_char  *p, *end;

    if (uri->len > 8 && ngx_strncmp(uri->data, "https://", 8) == 0) {
        p = uri->data + 8;
    } else if (uri->len > 7 && ngx_strncmp(uri->data, "http://", 7) == 0) {
        p = uri->data + 7;
    } else {
        /* Already a path-only value */
        *path = *uri;
        return;
    }

    end = uri->data + uri->len;

    /* Advance past host[:port] to find the path separator */
    while (p < end && *p != '/') {
        p++;
    }

    if (p < end) {
        path->data = p;
        path->len  = end - p;
    } else {
        ngx_str_set(path, "/");
    }
}

/* ---------------------------------------------------------------------------
 * Helper: Cookie ヘッダ値から正確な Cookie 名で検索する
 * Issue 9 対応: ngx_strnstr の部分文字列マッチを廃止し、
 * "not_oidc_auth=value" のような誤マッチを防ぐ。
 * また値が空でないことも確認する（Issue 2 の最低限の対処）。
 * --------------------------------------------------------------------------- */
static ngx_uint_t
ngx_http_oidc_cookie_exists(u_char *cookie_data, size_t cookie_len,
    const char *name, size_t name_len)
{
    u_char  *p   = cookie_data;
    u_char  *end = cookie_data + cookie_len;
    u_char  *after;

    while (p < end) {
        /* Skip leading whitespace between cookies */
        while (p < end && (*p == ' ' || *p == '\t')) {
            p++;
        }

        /* Check if this entry starts with the cookie name */
        if ((size_t)(end - p) >= name_len
            && ngx_strncmp(p, (u_char *) name, name_len) == 0)
        {
            after = p + name_len;
            /* Must be followed by '=' to avoid prefix-match false positives */
            if (after < end && *after == '=') {
                after++; /* step past '=' */
                /* Cookie value must be non-empty */
                if (after < end && *after != ';') {
                    return 1;
                }
            }
        }

        /* Advance to the next cookie (past the next ';') */
        while (p < end && *p != ';') {
            p++;
        }
        if (p < end) {
            p++; /* skip ';' */
        }
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * Subrequest completion handler for OIDC discovery
 * Issue 4:  発見結果を conf->cached_metadata に格納してリクエスト間で共有。
 * Issue 8:  メタデータの実データを ngx_cycle->pool に確保してダングリングを防止。
 * Issue 11: JSON パース失敗時に NGX_ERROR を返してエラーを明示的に伝播。
 * --------------------------------------------------------------------------- */
static ngx_int_t
ngx_http_oidc_discovery_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_oidc_ctx_t            *ctx;
    ngx_http_oidc_loc_conf_t       *conf;
    ngx_http_oidc_provider_metadata_t *metadata;
    ngx_str_t                       response_body;
    u_char                         *json_data;
    size_t                          json_len;

    ctx = ngx_http_get_module_ctx(r->parent, ngx_http_oidc_module);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    conf = ngx_http_get_module_loc_conf(r->parent, ngx_http_oidc_module);

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Discovery request failed, status: %ui",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Discovery request returned no upstream buffer");
        return NGX_ERROR;
    }

    response_body.len  = r->upstream->buffer.last - r->upstream->buffer.pos;
    response_body.data = r->upstream->buffer.pos;

    if (response_body.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Discovery response body is empty");
        return NGX_ERROR;
    }

    /* Copy body into the subrequest pool (used only during this call) */
    json_len  = response_body.len;
    json_data = ngx_palloc(r->pool, json_len);
    if (json_data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(json_data, response_body.data, json_len);

    /*
     * Allocate metadata in ngx_cycle->pool so it outlives this request
     * and can be reused by subsequent requests in this worker process.
     * (Issue 4 / Issue 8)
     */
    metadata = ngx_pcalloc(ngx_cycle->pool,
                            sizeof(ngx_http_oidc_provider_metadata_t));
    if (metadata == NULL) {
        return NGX_ERROR;
    }

    /*
     * Pass ngx_cycle->pool so string data is also allocated there,
     * preventing dangling pointers after the subrequest is destroyed.
     * (Issue 8)
     */
    if (ngx_http_oidc_parse_discovery_json(r->parent, ngx_cycle->pool,
                                            json_data, json_len, metadata)
        != NGX_OK)
    {
        /* Issue 11: propagate error instead of silently returning NGX_OK */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Failed to parse discovery JSON");
        return NGX_ERROR;
    }

    /* Cache in loc_conf for all subsequent requests in this worker */
    conf->cached_metadata = metadata;

    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                  "OIDC: Discovery successful, metadata cached in worker");

    return NGX_OK;
}

/*
 * Start Discovery Subrequest
 */
static ngx_int_t
ngx_http_oidc_start_discovery(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *conf)
{
    ngx_http_request_t         *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_str_t                   discovery_uri = ngx_string("/_oidc_discovery");
    ngx_str_t                   discovery_args;
    const char                 *discovery_path = "/.well-known/openid-configuration";
    size_t                      len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);

    /* "url=" is 4 characters */
    len = 4 + conf->oidc_provider.len + ngx_strlen(discovery_path);

    discovery_args.data = ngx_palloc(r->pool, len + 1);
    if (discovery_args.data == NULL) {
        return NGX_ERROR;
    }

    discovery_args.len = ngx_snprintf(discovery_args.data, len + 1,
                                       "url=%V%s",
                                       &conf->oidc_provider, discovery_path)
                         - discovery_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_discovery_handler;
    psr->data    = NULL;

    if (ctx) {
        ctx->discovery_attempted = 1;
    }

    if (ngx_http_subrequest(r, &discovery_uri, &discovery_args, &sr, psr,
                             NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

/*
 * JSON Parsing Function for Discovery Metadata
 *
 * Issue 8 対応: プールを呼び出し元から受け取ることで、
 * 文字列データの確保先を呼び出し元が制御できるようにした。
 */
static ngx_int_t
ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r, ngx_pool_t *pool,
    const u_char *data, size_t len,
    ngx_http_oidc_provider_metadata_t *metadata)
{
    json_error_t  error;
    json_t       *root;
    json_t       *val;
    const char   *str;
    size_t        str_len;

    root = json_loadb((const char *) data, len, 0, &error);
    if (!root) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JSON parsing error on line %d: %s",
                      error.line, error.text);
        return NGX_ERROR;
    }

    if (!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JSON root is not an object");
        json_decref(root);
        return NGX_ERROR;
    }

    val = json_object_get(root, "authorization_endpoint");
    if (json_is_string(val)) {
        str     = json_string_value(val);
        str_len = ngx_strlen(str);
        metadata->authorization_endpoint.data = ngx_palloc(pool, str_len + 1);
        if (metadata->authorization_endpoint.data) {
            ngx_memcpy(metadata->authorization_endpoint.data, str, str_len);
            metadata->authorization_endpoint.data[str_len] = '\0';
            metadata->authorization_endpoint.len = str_len;
        }
    }

    val = json_object_get(root, "token_endpoint");
    if (json_is_string(val)) {
        str     = json_string_value(val);
        str_len = ngx_strlen(str);
        metadata->token_endpoint.data = ngx_palloc(pool, str_len + 1);
        if (metadata->token_endpoint.data) {
            ngx_memcpy(metadata->token_endpoint.data, str, str_len);
            metadata->token_endpoint.data[str_len] = '\0';
            metadata->token_endpoint.len = str_len;
        }
    }

    val = json_object_get(root, "jwks_uri");
    if (json_is_string(val)) {
        str     = json_string_value(val);
        str_len = ngx_strlen(str);
        metadata->jwks_uri.data = ngx_palloc(pool, str_len + 1);
        if (metadata->jwks_uri.data) {
            ngx_memcpy(metadata->jwks_uri.data, str, str_len);
            metadata->jwks_uri.data[str_len] = '\0';
            metadata->jwks_uri.len = str_len;
        }
    }

    json_decref(root);
    return NGX_OK;
}

/*
 * Configuration creation function
 */
static void *
ngx_http_oidc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /* Issue 6: NGX_CONF_UNSET is the canonical "not yet set" sentinel */
    conf->auth_oidc       = NGX_CONF_UNSET;
    conf->cached_metadata = NULL;

    return conf;
}

/*
 * Configuration merging function
 */
static char *
ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

    /* Issue 6: ngx_conf_merge_value handles NGX_CONF_UNSET correctly */
    ngx_conf_merge_value(conf->auth_oidc,    prev->auth_oidc,    0);
    ngx_conf_merge_str_value(conf->oidc_provider, prev->oidc_provider, "");
    ngx_conf_merge_str_value(conf->client_id,     prev->client_id,     "");
    ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
    ngx_conf_merge_str_value(conf->redirect_uri,  prev->redirect_uri,  "");

    return NGX_CONF_OK;
}

/*
 * Module Directives
 */
static ngx_command_t ngx_http_oidc_commands[] = {

    /*
     * Issue 6: auth_oidc を NGX_CONF_FLAG + ngx_conf_set_flag_slot に変更。
     * "on"/"off" 以外の値はロード時にエラーになる。
     */
    { ngx_string("auth_oidc"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, auth_oidc),
      NULL },

    { ngx_string("oidc_provider"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_provider),
      NULL },

    { ngx_string("oidc_client_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_id),
      NULL },

    { ngx_string("oidc_client_secret"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_secret),
      NULL },

    { ngx_string("oidc_redirect_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redirect_uri),
      NULL },

    ngx_null_command
};

/*
 * Subrequest handler for OIDC token endpoint
 */
static ngx_int_t
ngx_http_oidc_token_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_str_t    response_body;
    u_char      *json_data;
    size_t       json_len;
    json_error_t error;
    json_t      *root;
    json_t      *id_token;
    json_t      *access_token;

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Token request failed, status: %ui",
                      r->headers_out.status);
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Token request returned no upstream buffer");
        return NGX_ERROR;
    }

    response_body.len  = r->upstream->buffer.last - r->upstream->buffer.pos;
    response_body.data = r->upstream->buffer.pos;

    if (response_body.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Token response body is empty");
        goto done;
    }

    json_len  = response_body.len;
    json_data = ngx_palloc(r->pool, json_len);
    if (json_data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(json_data, response_body.data, json_len);

    root = json_loadb((const char *) json_data, json_len, 0, &error);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JSON parsing error for token response: %s",
                      error.text);
        goto done;
    }

    if (!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JSON root is not an object for token response");
        json_decref(root);
        goto done;
    }

    id_token     = json_object_get(root, "id_token");
    access_token = json_object_get(root, "access_token");

    if (json_is_string(id_token) && json_is_string(access_token)) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "OIDC: Successfully retrieved tokens");
        /*
         * TODO Phase 4: Validate JWT signature (using jwks_uri), verify expiry
         * and nonce, then issue a signed (HMAC) session cookie so that the
         * cookie-check in the access handler cannot be trivially forged.
         */
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Missing id_token or access_token in response");
    }

    json_decref(root);

done:
    /* Resume the parent request */
    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

/*
 * Initiate Token Subrequest
 */
static ngx_int_t
ngx_http_oidc_start_token_request(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *conf, ngx_str_t *code)
{
    ngx_http_request_t         *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_str_t                   token_uri = ngx_string("/_oidc_token");
    ngx_str_t                   token_args;
    u_char                     *p;
    size_t                      code_enc_len, client_id_enc_len;
    size_t                      client_secret_enc_len, redirect_uri_enc_len;
    size_t                      len;

    code_enc_len = code->len
                 + 2 * ngx_escape_uri(NULL, code->data, code->len,
                                       NGX_ESCAPE_ARGS);
    client_id_enc_len = conf->client_id.len
                      + 2 * ngx_escape_uri(NULL, conf->client_id.data,
                                            conf->client_id.len,
                                            NGX_ESCAPE_ARGS);
    client_secret_enc_len = conf->client_secret.len
                          + 2 * ngx_escape_uri(NULL, conf->client_secret.data,
                                                conf->client_secret.len,
                                                NGX_ESCAPE_ARGS);
    redirect_uri_enc_len = conf->redirect_uri.len
                         + 2 * ngx_escape_uri(NULL, conf->redirect_uri.data,
                                               conf->redirect_uri.len,
                                               NGX_ESCAPE_ARGS);

    /* "code=&client_id=&client_secret=&redirect_uri=&grant_type=authorization_code" */
    len = sizeof("code=") - 1 + code_enc_len
        + sizeof("&client_id=") - 1 + client_id_enc_len
        + sizeof("&client_secret=") - 1 + client_secret_enc_len
        + sizeof("&redirect_uri=") - 1 + redirect_uri_enc_len
        + sizeof("&grant_type=authorization_code") - 1;

    token_args.data = ngx_palloc(r->pool, len + 1);
    if (token_args.data == NULL) {
        return NGX_ERROR;
    }

    p = token_args.data;

    p = ngx_cpymem(p, "code=", sizeof("code=") - 1);
    if (code_enc_len == code->len) {
        p = ngx_cpymem(p, code->data, code->len);
    } else {
        p = (u_char *) ngx_escape_uri(p, code->data, code->len,
                                       NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    if (client_id_enc_len == conf->client_id.len) {
        p = ngx_cpymem(p, conf->client_id.data, conf->client_id.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_id.data,
                                       conf->client_id.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&client_secret=", sizeof("&client_secret=") - 1);
    if (client_secret_enc_len == conf->client_secret.len) {
        p = ngx_cpymem(p, conf->client_secret.data, conf->client_secret.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_secret.data,
                                       conf->client_secret.len,
                                       NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    if (redirect_uri_enc_len == conf->redirect_uri.len) {
        p = ngx_cpymem(p, conf->redirect_uri.data, conf->redirect_uri.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->redirect_uri.data,
                                       conf->redirect_uri.len,
                                       NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&grant_type=authorization_code",
                    sizeof("&grant_type=authorization_code") - 1);

    token_args.len = p - token_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_token_handler;
    psr->data    = NULL;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx) {
        ctx->token_attempted = 1;
    }

    if (ngx_http_subrequest(r, &token_uri, &token_args, &sr, psr,
                             NGX_HTTP_SUBREQUEST_IN_MEMORY)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

/*
 * Redirect to Identity Provider
 *
 * Issue 1 対応: state と nonce を RAND_bytes による暗号論的乱数から生成。
 */
static ngx_int_t
ngx_http_oidc_redirect_to_idp(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *conf,
    ngx_http_oidc_provider_metadata_t *metadata)
{
    ngx_table_elt_t  *location;
    ngx_str_t        *auth_endpoint = &metadata->authorization_endpoint;
    ngx_str_t         state, nonce;
    u_char           *p;
    size_t            len;
    size_t            client_id_enc_len, redirect_uri_enc_len;

    if (auth_endpoint->len == 0
        || conf->client_id.len == 0
        || conf->redirect_uri.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Missing authorization_endpoint, client_id,"
                      " or redirect_uri");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * Issue 1: 16 バイト (128 bit) の暗号論的乱数を 16 進数文字列として生成。
     * 固定値 "random_state_123" / "random_nonce_123" を廃止。
     *
     * NOTE: state と nonce はここで生成後に Cookie に署名付きで保存し、
     * コールバック時に検証することで CSRF / リプレイ攻撃を防ぐ必要がある。
     * その検証ロジックは Phase 4 で実装する (TODO)。
     */
    if (ngx_http_oidc_generate_random_hex(r->pool, 16, &state) != NGX_OK
        || ngx_http_oidc_generate_random_hex(r->pool, 16, &nonce) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Failed to generate random state/nonce");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    client_id_enc_len = conf->client_id.len
                      + 2 * ngx_escape_uri(NULL, conf->client_id.data,
                                            conf->client_id.len,
                                            NGX_ESCAPE_ARGS);
    redirect_uri_enc_len = conf->redirect_uri.len
                         + 2 * ngx_escape_uri(NULL, conf->redirect_uri.data,
                                               conf->redirect_uri.len,
                                               NGX_ESCAPE_ARGS);

    len = auth_endpoint->len
        + sizeof("?response_type=code&scope=openid&client_id=") - 1
        + client_id_enc_len
        + sizeof("&redirect_uri=") - 1 + redirect_uri_enc_len
        + sizeof("&state=") - 1 + state.len
        + sizeof("&nonce=") - 1 + nonce.len;

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");

    location->value.data = ngx_pnalloc(r->pool, len);
    if (location->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = location->value.data;
    p = ngx_cpymem(p, auth_endpoint->data, auth_endpoint->len);
    p = ngx_cpymem(p, "?response_type=code&scope=openid&client_id=",
                    sizeof("?response_type=code&scope=openid&client_id=") - 1);

    if (client_id_enc_len == conf->client_id.len) {
        p = ngx_cpymem(p, conf->client_id.data, conf->client_id.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_id.data,
                                       conf->client_id.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    if (redirect_uri_enc_len == conf->redirect_uri.len) {
        p = ngx_cpymem(p, conf->redirect_uri.data, conf->redirect_uri.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->redirect_uri.data,
                                       conf->redirect_uri.len,
                                       NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&state=", sizeof("&state=") - 1);
    p = ngx_cpymem(p, state.data, state.len);
    p = ngx_cpymem(p, "&nonce=", sizeof("&nonce=") - 1);
    p = ngx_cpymem(p, nonce.data, nonce.len);

    location->value.len = p - location->value.data;

    r->headers_out.location = location;

    /*
     * TODO Phase 4: Set a signed (HMAC-SHA256) cookie containing state and
     * nonce so they can be verified when the IdP redirects back.
     */

    return NGX_HTTP_MOVED_TEMPORARILY;
}

/*
 * Access Phase Handler
 */
static ngx_int_t
ngx_http_oidc_access_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t           *conf;
    ngx_http_oidc_ctx_t                *ctx;
    ngx_http_oidc_provider_metadata_t  *metadata;
    ngx_str_t                           redirect_path;
    ngx_uint_t                          i, authenticated;
    ngx_list_part_t                    *part;
    ngx_table_elt_t                    *header;
    ngx_str_t                           code_key;
    ngx_str_t                           code_value;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    /* Issue 6: conf->auth_oidc は ngx_flag_t; 0 (off) なら素通り */
    if (!conf->auth_oidc) {
        return NGX_DECLINED;
    }

    /* Skip subrequests to avoid handler loops */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);
    }

    /*
     * Issue 4: ワーカープロセスレベルのキャッシュを優先参照。
     * キャッシュが空かつプロバイダが設定されていれば Discovery を開始する。
     */
    metadata = conf->cached_metadata;

    if (conf->oidc_provider.len > 0 && metadata == NULL) {
        if (ctx->discovery_attempted) {
            /*
             * Discovery サブリクエストは送ったが metadata がまだ NULL のまま
             * access phase が再実行された = Discovery 失敗。
             * Issue 10: ctx はリクエスト単位で新規生成されるため、
             * 次のリクエストでは自動的に再試行される（正しい挙動）。
             */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: Discovery failed for this request");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        return ngx_http_oidc_start_discovery(r, conf);
    }

    if (metadata == NULL) {
        /* oidc_provider 未設定の場合は素通り */
        return NGX_DECLINED;
    }

    /*
     * Issue 5: redirect_uri がフル URL でも r->uri（パスのみ）と正しく比較
     * できるよう、パス部分だけを抽出して比較する。
     */
    ngx_http_oidc_extract_path(&conf->redirect_uri, &redirect_path);

    if (redirect_path.len > 0
        && r->uri.len >= redirect_path.len
        && ngx_strncmp(r->uri.data, redirect_path.data,
                        redirect_path.len) == 0)
    {
        if (ctx->token_attempted) {
            /*
             * トークン交換は既に試みた。Phase 4 でセッション Cookie を
             * 発行してリダイレクトするまでの間は素通りさせる。
             */
            return NGX_DECLINED;
        }

        code_key.data = (u_char *) "code";
        code_key.len  = sizeof("code") - 1;

        if (ngx_http_arg(r, code_key.data, code_key.len, &code_value)
            == NGX_OK)
        {
            return ngx_http_oidc_start_token_request(r, conf, &code_value);
        }

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Missing code parameter in callback");
        return NGX_HTTP_BAD_REQUEST;
    }

    /*
     * セッション Cookie の存在確認。
     * Issue 9: ngx_http_oidc_cookie_exists() で Cookie 名の境界を正確に
     * チェックし、プレフィックス誤マッチを防ぐ。
     *
     * Issue 2 (TODO Phase 4): Cookie 値を HMAC/JWT で検証するまでは
     * Cookie の存在確認のみで認証済みとみなす — セキュリティ上不十分。
     */
    authenticated = 0;
    part   = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part   = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == sizeof("Cookie") - 1
            && ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie",
                                header[i].key.len) == 0)
        {
            if (ngx_http_oidc_cookie_exists(header[i].value.data,
                                             header[i].value.len,
                                             "oidc_auth",
                                             sizeof("oidc_auth") - 1))
            {
                authenticated = 1;
                break;
            }
        }
    }

    if (!authenticated) {
        return ngx_http_oidc_redirect_to_idp(r, conf, metadata);
    }

    return NGX_DECLINED;
}

/*
 * Post-configuration init function
 */
static ngx_int_t
ngx_http_oidc_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oidc_access_handler;

    return NGX_OK;
}

/*
 * Module Context
 */
static ngx_http_module_t ngx_http_oidc_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_oidc_init,                    /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_oidc_create_loc_conf,         /* create location configuration */
    ngx_http_oidc_merge_loc_conf           /* merge location configuration */
};

/*
 * Module Definition
 */
ngx_module_t ngx_http_oidc_module = {
    NGX_MODULE_V1,
    &ngx_http_oidc_module_ctx,             /* module context */
    ngx_http_oidc_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
