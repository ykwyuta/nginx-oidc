#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <jwt.h>

/*
 * Provider Metadata Structure
 */
typedef struct {
    ngx_str_t authorization_endpoint;
    ngx_str_t token_endpoint;
    ngx_str_t jwks_uri;
} ngx_http_oidc_provider_metadata_t;

/*
 * Claim structure to hold JWT payload
 */
typedef struct {
    ngx_str_t sub;
    ngx_str_t email;
    ngx_str_t name;
} ngx_http_oidc_claims_t;

/*
 * Main Configuration Structure (for caching)
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    time_t discovery_expires;
    u_char hmac_secret[32];
    ngx_uint_t secret_initialized:1;
} ngx_http_oidc_main_conf_t;

/*
 * Module Configuration Structure
 */
typedef struct {
    ngx_flag_t   auth_oidc;       /* Expected to hold the OIDC configuration name or switch */
    ngx_str_t    oidc_provider;   /* Expected to hold the OIDC provider string */
    ngx_str_t    client_id;
    ngx_str_t    client_secret;
    ngx_str_t    redirect_uri;
} ngx_http_oidc_loc_conf_t;

/*
 * Request Context Structure
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    ngx_uint_t discovery_attempted:1;
    ngx_uint_t token_attempted:1;
    ngx_str_t id_token;
    ngx_http_oidc_claims_t claims;
} ngx_http_oidc_ctx_t;

/* Forward declaration for ngx_http_oidc_module */
extern ngx_module_t ngx_http_oidc_module;

/* Forward declaration for JSON Parser */
static ngx_int_t ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r, const u_char *data, size_t len, ngx_http_oidc_provider_metadata_t *metadata);

/*
 * Subrequest completion handler for OIDC discovery
 */
static ngx_int_t ngx_http_oidc_discovery_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r->parent, ngx_http_oidc_module);
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r->parent, ngx_http_oidc_module);
    u_char *json_data = NULL;
    size_t json_len = 0;

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery request failed, status: %ui", r->headers_out.status);
        ctx->discovery_attempted = 0; /* Allow retry */
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery request returned no upstream buffer");
        return NGX_ERROR;
    }

    /* Simple extraction of the subrequest response body */
    ngx_str_t response_body;
    response_body.len = r->upstream->buffer.last - r->upstream->buffer.pos;
    response_body.data = r->upstream->buffer.pos;

    if (response_body.len > 0) {
        json_len = response_body.len;
        json_data = ngx_palloc(r->pool, json_len);
        if (json_data) {
            ngx_memcpy(json_data, response_body.data, json_len);
        }
    }

    if (json_data) {
        if (mcf && mcf->metadata == NULL) {
            mcf->metadata = ngx_pcalloc(ngx_cycle->pool, sizeof(ngx_http_oidc_provider_metadata_t));
        }

        if (mcf && mcf->metadata) {
            if (ngx_http_oidc_parse_discovery_json(r->parent, json_data, json_len, mcf->metadata) == NGX_OK) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: Discovery successful");
                ctx->metadata = mcf->metadata;
            } else {
                mcf->metadata = NULL;
                ctx->discovery_attempted = 0; /* Allow retry */
                return NGX_ERROR;
            }
        }
    }

    /* Resume the main request */
    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

/*
 * Start Discovery Subrequest
 */
static ngx_int_t ngx_http_oidc_start_discovery(ngx_http_request_t *r, ngx_http_oidc_loc_conf_t *conf) {
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ngx_str_t discovery_uri = ngx_string("/_oidc_discovery");
    ngx_str_t discovery_args;
    const char *discovery_path = "/.well-known/openid-configuration";
    /* "url=" is 4 characters */
    size_t len = 4 + conf->oidc_provider.len + ngx_strlen(discovery_path);

    discovery_args.data = ngx_palloc(r->pool, len + 1);
    if (discovery_args.data == NULL) {
        return NGX_ERROR;
    }

    discovery_args.len = ngx_snprintf(discovery_args.data, len + 1, "url=%V%s", &conf->oidc_provider, discovery_path) - discovery_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_discovery_handler;
    psr->data = NULL;

    if (ctx) {
        ctx->discovery_attempted = 1;
    }

    if (ngx_http_subrequest(r, &discovery_uri, &discovery_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

/*
 * JSON Parsing Function for Discovery Metadata
 */
static ngx_int_t ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r, const u_char *data, size_t len, ngx_http_oidc_provider_metadata_t *metadata) {
    json_error_t error;
    json_t *root = json_loadb((const char *)data, len, 0, &error);

    if (!root) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JSON parsing error: on line %d: %s", error.line, error.text);
        return NGX_ERROR;
    }

    if (!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JSON root is not an object");
        json_decref(root);
        return NGX_ERROR;
    }

    json_t *auth_end = json_object_get(root, "authorization_endpoint");
    if (json_is_string(auth_end)) {
        const char *val = json_string_value(auth_end);
        metadata->authorization_endpoint.len = ngx_strlen(val);
        metadata->authorization_endpoint.data = ngx_palloc(ngx_cycle->pool, metadata->authorization_endpoint.len + 1);
        if (metadata->authorization_endpoint.data) {
            ngx_memcpy(metadata->authorization_endpoint.data, val, metadata->authorization_endpoint.len);
            metadata->authorization_endpoint.data[metadata->authorization_endpoint.len] = '\0';
        }
    }

    json_t *token_end = json_object_get(root, "token_endpoint");
    if (json_is_string(token_end)) {
        const char *val = json_string_value(token_end);
        metadata->token_endpoint.len = ngx_strlen(val);
        metadata->token_endpoint.data = ngx_palloc(ngx_cycle->pool, metadata->token_endpoint.len + 1);
        if (metadata->token_endpoint.data) {
            ngx_memcpy(metadata->token_endpoint.data, val, metadata->token_endpoint.len);
            metadata->token_endpoint.data[metadata->token_endpoint.len] = '\0';
        }
    }

    json_t *jwks_uri = json_object_get(root, "jwks_uri");
    if (json_is_string(jwks_uri)) {
        const char *val = json_string_value(jwks_uri);
        metadata->jwks_uri.len = ngx_strlen(val);
        metadata->jwks_uri.data = ngx_palloc(ngx_cycle->pool, metadata->jwks_uri.len + 1);
        if (metadata->jwks_uri.data) {
            ngx_memcpy(metadata->jwks_uri.data, val, metadata->jwks_uri.len);
            metadata->jwks_uri.data[metadata->jwks_uri.len] = '\0';
        }
    }

    json_decref(root);
    return NGX_OK;
}

/*
 * Configuration creation function
 */
static void *ngx_http_oidc_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_oidc_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->auth_oidc = NGX_CONF_UNSET;

    return conf;
}

/*
 * Configuration merging function
 */
static char *ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->auth_oidc, prev->auth_oidc, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->oidc_provider, prev->oidc_provider, "");
    ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
    ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
    ngx_conf_merge_str_value(conf->redirect_uri, prev->redirect_uri, "");

    return NGX_CONF_OK;
}

/*
 * Module Directives
 */
static ngx_command_t ngx_http_oidc_commands[] = {

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

static ngx_int_t ngx_http_oidc_start_jwks_request(ngx_http_request_t *r);

/*
 * Subrequest handler for OIDC token endpoint
 */
static ngx_int_t ngx_http_oidc_token_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r->parent, ngx_http_oidc_module);
    u_char *json_data = NULL;
    size_t json_len = 0;

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Token request failed, status: %ui", r->headers_out.status);
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Token request returned no upstream buffer");
        return NGX_ERROR;
    }

    /* Extract the subrequest response body */
    ngx_str_t response_body;
    response_body.len = r->upstream->buffer.last - r->upstream->buffer.pos;
    response_body.data = r->upstream->buffer.pos;

    if (response_body.len > 0) {
        json_len = response_body.len;
        json_data = ngx_palloc(r->pool, json_len);
        if (json_data) {
            ngx_memcpy(json_data, response_body.data, json_len);
        }
    }

    if (json_data) {
        json_error_t error;
        json_t *root = json_loadb((const char *)json_data, json_len, 0, &error);

        if (root) {
            if (json_is_object(root)) {
                json_t *id_token = json_object_get(root, "id_token");
                json_t *access_token = json_object_get(root, "access_token");

                if (json_is_string(id_token) && json_is_string(access_token)) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: Successfully retrieved tokens");

                    const char *id_token_val = json_string_value(id_token);
                    ctx->id_token.len = ngx_strlen(id_token_val);
                    ctx->id_token.data = ngx_palloc(r->parent->pool, ctx->id_token.len + 1);
                    if (ctx->id_token.data) {
                        ngx_memcpy(ctx->id_token.data, id_token_val, ctx->id_token.len);
                        ctx->id_token.data[ctx->id_token.len] = '\0';

                        json_decref(root);

                        /* Start JWKS subrequest */
                        return ngx_http_oidc_start_jwks_request(r->parent);
                    }
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing id_token or access_token in response");
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JSON root is not an object for token response");
            }
            json_decref(root);
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JSON parsing error for token response: %s", error.text);
        }
    }

    /* Resume main request after subrequest completion */
    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_oidc_jwks_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);

/*
 * Start JWKS Subrequest
 */
static ngx_int_t ngx_http_oidc_start_jwks_request(ngx_http_request_t *r) {
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ngx_str_t jwks_subreq_uri = ngx_string("/_oidc_jwks");
    ngx_str_t jwks_args;
    size_t len;

    if (ctx == NULL || ctx->metadata == NULL || ctx->metadata->jwks_uri.len == 0) {
        return NGX_ERROR;
    }

    len = sizeof("url=") - 1 + ctx->metadata->jwks_uri.len;
    jwks_args.data = ngx_palloc(r->pool, len + 1);
    if (jwks_args.data == NULL) {
        return NGX_ERROR;
    }

    jwks_args.len = ngx_snprintf(jwks_args.data, len + 1, "url=%V", &ctx->metadata->jwks_uri) - jwks_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_jwks_handler;
    psr->data = NULL;

    if (ngx_http_subrequest(r, &jwks_subreq_uri, &jwks_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * JWKS Subrequest Handler
 */
static ngx_int_t ngx_http_oidc_jwks_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r->parent, ngx_http_oidc_module);
    u_char *json_data = NULL;
    size_t json_len = 0;

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JWKS request failed, status: %ui", r->headers_out.status);
        if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JWKS request returned no upstream buffer");
        if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
        return NGX_ERROR;
    }

    ngx_str_t response_body;
    response_body.len = r->upstream->buffer.last - r->upstream->buffer.pos;
    response_body.data = r->upstream->buffer.pos;

    if (response_body.len > 0) {
        json_len = response_body.len;
        json_data = ngx_palloc(r->pool, json_len);
        if (json_data) {
            ngx_memcpy(json_data, response_body.data, json_len);
        }
    }

    if (json_data) {
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: JWKS retrieved successfully");

        jwt_t *jwt = NULL;

        /* libjwt >= 1.15.3 supports jwt_decode() with JWKS JSON directly */
        int jwt_ret = jwt_decode(&jwt, (const char *)ctx->id_token.data, json_data, json_len);

        if (jwt_ret == 0 && jwt != NULL) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: JWT decoded and signature verified successfully using JWKS");

            time_t now = ngx_time();
            time_t exp = jwt_get_grant_int(jwt, "exp");
            if (exp > 0 && exp >= now) {

                /* Now verify the nonce */
                ngx_str_t nonce_cookie = ngx_null_string;
                ngx_uint_t i;
                ngx_list_part_t *part = &r->parent->headers_in.headers.part;
                ngx_table_elt_t *header = part->elts;

                for (i = 0; /* void */ ; i++) {
                    if (i >= part->nelts) {
                        if (part->next == NULL) break;
                        part = part->next;
                        header = part->elts;
                        i = 0;
                    }
                    if (header[i].key.len == sizeof("Cookie") - 1 &&
                        ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie", header[i].key.len) == 0) {
                        u_char *p = header[i].value.data;
                        u_char *end = p + header[i].value.len;
                        while (p < end) {
                            if (end - p >= 11 && ngx_strncmp(p, "oidc_nonce=", 11) == 0) {
                                p += 11;
                                nonce_cookie.data = p;
                                while (p < end && *p != ';') p++;
                                nonce_cookie.len = p - nonce_cookie.data;
                                break;
                            }
                            while (p < end && *p != ';') p++;
                            if (p < end) p++;
                            while (p < end && *p == ' ') p++;
                        }
                        if (nonce_cookie.data) break;
                    }
                }

                const char *jwt_nonce = jwt_get_grant(jwt, "nonce");
                if (nonce_cookie.data && jwt_nonce &&
                    ngx_strlen(jwt_nonce) == nonce_cookie.len &&
                    ngx_strncmp(jwt_nonce, nonce_cookie.data, nonce_cookie.len) == 0) {

                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: JWT valid and nonce matched");
                    ctx->token_attempted = 1;

                    /* Registration of variables and setting auth cookie comes here */
                    const char *sub = jwt_get_grant(jwt, "sub");
                    const char *email = jwt_get_grant(jwt, "email");
                    const char *name = jwt_get_grant(jwt, "name");

                    if (sub) {
                        ctx->claims.sub.len = ngx_strlen(sub);
                        ctx->claims.sub.data = ngx_palloc(r->parent->pool, ctx->claims.sub.len);
                        ngx_memcpy(ctx->claims.sub.data, sub, ctx->claims.sub.len);
                    }
                    if (email) {
                        ctx->claims.email.len = ngx_strlen(email);
                        ctx->claims.email.data = ngx_palloc(r->parent->pool, ctx->claims.email.len);
                        ngx_memcpy(ctx->claims.email.data, email, ctx->claims.email.len);
                    }
                    if (name) {
                        ctx->claims.name.len = ngx_strlen(name);
                        ctx->claims.name.data = ngx_palloc(r->parent->pool, ctx->claims.name.len);
                        ngx_memcpy(ctx->claims.name.data, name, ctx->claims.name.len);
                    }

                    /* Issue HMAC signed session cookie */
                    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r->parent, ngx_http_oidc_module);
                    if (mcf) {
                        if (!mcf->secret_initialized) {
                            if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) == 1) {
                                mcf->secret_initialized = 1;
                            }
                        }

                        if (mcf->secret_initialized) {
                            ngx_table_elt_t *set_cookie_auth;
                            u_char *p;

                            /* Generate a session identifier (e.g., username or sub + timestamp) */
                            ngx_str_t payload;
                            payload.len = ctx->claims.sub.len + 32;
                            payload.data = ngx_palloc(r->parent->pool, payload.len);
                            payload.len = ngx_snprintf(payload.data, payload.len, "%V:%T", &ctx->claims.sub, ngx_time()) - payload.data;

                            u_char mac[32];
                            u_char mac_hex[64];
                            unsigned int mac_len = 0;

                            HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
                                 payload.data, payload.len,
                                 mac, &mac_len);
                            ngx_hex_dump(mac_hex, mac, 32);

                            set_cookie_auth = ngx_list_push(&r->parent->headers_out.headers);
                            if (set_cookie_auth) {
                                set_cookie_auth->hash = 1;
                                ngx_str_set(&set_cookie_auth->key, "Set-Cookie");
                                set_cookie_auth->value.len = sizeof("oidc_auth=") - 1 + 64 + payload.len + sizeof("; HttpOnly; Path=/") - 1;
                                set_cookie_auth->value.data = ngx_pnalloc(r->parent->pool, set_cookie_auth->value.len);
                                if (set_cookie_auth->value.data) {
                                    p = set_cookie_auth->value.data;
                                    p = ngx_cpymem(p, "oidc_auth=", sizeof("oidc_auth=") - 1);
                                    p = ngx_cpymem(p, mac_hex, 64);
                                    p = ngx_cpymem(p, payload.data, payload.len);
                                    p = ngx_cpymem(p, "; HttpOnly; Path=/", sizeof("; HttpOnly; Path=/") - 1);
                                }
                            }
                        }
                    }

                    /* Clear state and nonce cookies */
                    ngx_table_elt_t *clear_state;
                    ngx_table_elt_t *clear_nonce;

                    clear_state = ngx_list_push(&r->parent->headers_out.headers);
                    if (clear_state) {
                        clear_state->hash = 1;
                        ngx_str_set(&clear_state->key, "Set-Cookie");
                        ngx_str_set(&clear_state->value, "oidc_state=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/");
                    }

                    clear_nonce = ngx_list_push(&r->parent->headers_out.headers);
                    if (clear_nonce) {
                        clear_nonce->hash = 1;
                        ngx_str_set(&clear_nonce->key, "Set-Cookie");
                        ngx_str_set(&clear_nonce->value, "oidc_nonce=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/");
                    }

                    /* Provide redirect to original URL */
                    ngx_table_elt_t *location;
                    location = ngx_list_push(&r->parent->headers_out.headers);
                    if (location) {
                        location->hash = 1;
                        ngx_str_set(&location->key, "Location");
                        /* Use redirect_uri path for now or original request URI */
                        ngx_str_set(&location->value, "/");
                        r->parent->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
                        r->parent->headers_out.location = location;
                    }

                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JWT nonce mismatch or missing");
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: JWT expired or invalid exp");
            }
            jwt_free(jwt);
        } else {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Failed to decode JWT or signature invalid. jwt_decode returned: %d", jwt_ret);
        }
    }

    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

/*
 * Initiate Token Subrequest
 */
static ngx_int_t ngx_http_oidc_start_token_request(ngx_http_request_t *r, ngx_http_oidc_loc_conf_t *conf, ngx_str_t *code) {
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_str_t token_uri = ngx_string("/_oidc_token");
    ngx_str_t token_args;
    u_char *p;

    size_t code_enc_len = code->len + 2 * ngx_escape_uri(NULL, code->data, code->len, NGX_ESCAPE_ARGS);
    size_t client_id_enc_len = conf->client_id.len + 2 * ngx_escape_uri(NULL, conf->client_id.data, conf->client_id.len, NGX_ESCAPE_ARGS);
    size_t client_secret_enc_len = conf->client_secret.len + 2 * ngx_escape_uri(NULL, conf->client_secret.data, conf->client_secret.len, NGX_ESCAPE_ARGS);
    size_t redirect_uri_enc_len = conf->redirect_uri.len + 2 * ngx_escape_uri(NULL, conf->redirect_uri.data, conf->redirect_uri.len, NGX_ESCAPE_ARGS);

    /* "code=&client_id=&client_secret=&redirect_uri=&grant_type=authorization_code" */
    size_t len = sizeof("code=") - 1 + code_enc_len
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
        p = (u_char *) ngx_escape_uri(p, code->data, code->len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    if (client_id_enc_len == conf->client_id.len) {
        p = ngx_cpymem(p, conf->client_id.data, conf->client_id.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_id.data, conf->client_id.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&client_secret=", sizeof("&client_secret=") - 1);
    if (client_secret_enc_len == conf->client_secret.len) {
        p = ngx_cpymem(p, conf->client_secret.data, conf->client_secret.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_secret.data, conf->client_secret.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    if (redirect_uri_enc_len == conf->redirect_uri.len) {
        p = ngx_cpymem(p, conf->redirect_uri.data, conf->redirect_uri.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->redirect_uri.data, conf->redirect_uri.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&grant_type=authorization_code", sizeof("&grant_type=authorization_code") - 1);

    token_args.len = p - token_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_token_handler;
    psr->data = NULL;

    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx) {
        ctx->token_attempted = 1;
    }

    if (ngx_http_subrequest(r, &token_uri, &token_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_AGAIN;
}

/*
 * Redirect to Identity Provider
 */
static ngx_int_t ngx_http_oidc_redirect_to_idp(ngx_http_request_t *r, ngx_http_oidc_loc_conf_t *conf, ngx_http_oidc_ctx_t *ctx) {
    ngx_table_elt_t *location;
    ngx_table_elt_t *set_cookie_state;
    ngx_table_elt_t *set_cookie_nonce;
    ngx_str_t *auth_endpoint = &ctx->metadata->authorization_endpoint;
    u_char *p;
    size_t len;

    u_char state_buf[32];
    u_char nonce_buf[32];
    u_char state_hex[64];
    u_char nonce_hex[64];
    ngx_str_t state;
    ngx_str_t nonce;

    if (RAND_bytes(state_buf, 32) != 1 || RAND_bytes(nonce_buf, 32) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Failed to generate random bytes for state/nonce");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_hex_dump(state_hex, state_buf, 32);
    ngx_hex_dump(nonce_hex, nonce_buf, 32);
    state.data = state_hex;
    state.len = 64;
    nonce.data = nonce_hex;
    nonce.len = 64;

    if (auth_endpoint->len == 0 || conf->client_id.len == 0 || conf->redirect_uri.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing authorization_endpoint, client_id, or redirect_uri");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    size_t client_id_enc_len = conf->client_id.len + 2 * ngx_escape_uri(NULL, conf->client_id.data, conf->client_id.len, NGX_ESCAPE_ARGS);
    size_t redirect_uri_enc_len = conf->redirect_uri.len + 2 * ngx_escape_uri(NULL, conf->redirect_uri.data, conf->redirect_uri.len, NGX_ESCAPE_ARGS);

    /* Calculate URL length:
     * auth_endpoint + "?response_type=code&scope=openid&client_id=" + client_id
     * + "&redirect_uri=" + redirect_uri + "&state=" + state + "&nonce=" + nonce
     */
    len = auth_endpoint->len + sizeof("?response_type=code&scope=openid&client_id=") - 1
        + client_id_enc_len + sizeof("&redirect_uri=") - 1 + redirect_uri_enc_len
        + sizeof("&state=") - 1 + state.len + sizeof("&nonce=") - 1 + nonce.len;

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
    p = ngx_cpymem(p, "?response_type=code&scope=openid&client_id=", sizeof("?response_type=code&scope=openid&client_id=") - 1);
    if (client_id_enc_len == conf->client_id.len) {
        p = ngx_cpymem(p, conf->client_id.data, conf->client_id.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->client_id.data, conf->client_id.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    if (redirect_uri_enc_len == conf->redirect_uri.len) {
        p = ngx_cpymem(p, conf->redirect_uri.data, conf->redirect_uri.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->redirect_uri.data, conf->redirect_uri.len, NGX_ESCAPE_ARGS);
    }

    p = ngx_cpymem(p, "&state=", sizeof("&state=") - 1);
    p = ngx_cpymem(p, state.data, state.len);
    p = ngx_cpymem(p, "&nonce=", sizeof("&nonce=") - 1);
    p = ngx_cpymem(p, nonce.data, nonce.len);

    location->value.len = p - location->value.data;

    r->headers_out.location = location;

    /* Set Cookie for state */
    set_cookie_state = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_state == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    set_cookie_state->hash = 1;
    ngx_str_set(&set_cookie_state->key, "Set-Cookie");
    set_cookie_state->value.len = sizeof("oidc_state=") - 1 + state.len + sizeof("; HttpOnly") - 1;
    set_cookie_state->value.data = ngx_pnalloc(r->pool, set_cookie_state->value.len);
    if (set_cookie_state->value.data) {
        p = set_cookie_state->value.data;
        p = ngx_cpymem(p, "oidc_state=", sizeof("oidc_state=") - 1);
        p = ngx_cpymem(p, state.data, state.len);
        p = ngx_cpymem(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
    }

    /* Set Cookie for nonce */
    set_cookie_nonce = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_nonce == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    set_cookie_nonce->hash = 1;
    ngx_str_set(&set_cookie_nonce->key, "Set-Cookie");
    set_cookie_nonce->value.len = sizeof("oidc_nonce=") - 1 + nonce.len + sizeof("; HttpOnly") - 1;
    set_cookie_nonce->value.data = ngx_pnalloc(r->pool, set_cookie_nonce->value.len);
    if (set_cookie_nonce->value.data) {
        p = set_cookie_nonce->value.data;
        p = ngx_cpymem(p, "oidc_nonce=", sizeof("oidc_nonce=") - 1);
        p = ngx_cpymem(p, nonce.data, nonce.len);
        p = ngx_cpymem(p, "; HttpOnly", sizeof("; HttpOnly") - 1);
    }

    return NGX_HTTP_MOVED_TEMPORARILY;
}

/*
 * Access Phase Handler
 */
static ngx_int_t ngx_http_oidc_access_handler(ngx_http_request_t *r) {
    ngx_http_oidc_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    ngx_http_oidc_ctx_t *ctx;

    if (conf->auth_oidc == NGX_CONF_UNSET || conf->auth_oidc == 0) {
        return NGX_DECLINED;
    }

    /* Skip if this is a subrequest itself to avoid loops */
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

    if (mcf && mcf->metadata != NULL) {
        ctx->metadata = mcf->metadata;
    }

    if (conf->oidc_provider.len > 0 && ctx->metadata == NULL) {
        if (ctx->discovery_attempted) {
            /* Discovery failed for this request context. Do not retry in the *same* request */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery failed previously in this request");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Metadata not loaded yet, initiate discovery */
        return ngx_http_oidc_start_discovery(r, conf);
    }

    /* If metadata is loaded, check for authentication */
    if (ctx->metadata != NULL) {
        /* Check if this is the callback path */
        u_char *redirect_path = conf->redirect_uri.data;
        size_t redirect_path_len = conf->redirect_uri.len;
        if (conf->redirect_uri.len >= 7 && ngx_strncmp(conf->redirect_uri.data, "http://", 7) == 0) {
            u_char *p = (u_char *) ngx_strchr(conf->redirect_uri.data + 7, '/');
            if (p) {
                redirect_path = p;
                redirect_path_len = conf->redirect_uri.len - (p - conf->redirect_uri.data);
            }
        } else if (conf->redirect_uri.len >= 8 && ngx_strncmp(conf->redirect_uri.data, "https://", 8) == 0) {
            u_char *p = (u_char *) ngx_strchr(conf->redirect_uri.data + 8, '/');
            if (p) {
                redirect_path = p;
                redirect_path_len = conf->redirect_uri.len - (p - conf->redirect_uri.data);
            }
        }

        if (redirect_path_len > 0 && r->uri.len >= redirect_path_len &&
            ngx_strncmp(r->uri.data, redirect_path, redirect_path_len) == 0) {

            if (ctx->token_attempted) {
                /* We already attempted the token request and the phase is running again.
                 * To avoid infinite loop, we must decline here or assume authentication
                 * state from phase 4 logic (which is not fully implemented yet).
                 * For now, just allow it to proceed to avoid hanging. */
                return NGX_DECLINED;
            }

            /* Validate state parameter against oidc_state cookie to prevent CSRF */
            ngx_str_t state_param = ngx_null_string;
            ngx_str_t state_cookie = ngx_null_string;

            ngx_http_arg(r, (u_char *) "state", 5, &state_param);

            {
                ngx_uint_t j;
                ngx_list_part_t *spart = &r->headers_in.headers.part;
                ngx_table_elt_t *sheader = spart->elts;
                for (j = 0; /* void */ ; j++) {
                    if (j >= spart->nelts) {
                        if (spart->next == NULL) break;
                        spart = spart->next;
                        sheader = spart->elts;
                        j = 0;
                    }
                    if (sheader[j].key.len == sizeof("Cookie") - 1 &&
                        ngx_strncasecmp(sheader[j].key.data, (u_char *) "Cookie", sheader[j].key.len) == 0) {
                        u_char *sp = sheader[j].value.data;
                        u_char *send = sp + sheader[j].value.len;
                        while (sp < send) {
                            if (send - sp >= 11 && ngx_strncmp(sp, "oidc_state=", 11) == 0) {
                                sp += 11;
                                state_cookie.data = sp;
                                while (sp < send && *sp != ';') sp++;
                                state_cookie.len = sp - state_cookie.data;
                                break;
                            }
                            while (sp < send && *sp != ';') sp++;
                            if (sp < send) sp++;
                            while (sp < send && *sp == ' ') sp++;
                        }
                        if (state_cookie.data) break;
                    }
                }
            }

            if (state_param.len == 0 || state_cookie.len == 0
                || state_param.len != state_cookie.len
                || ngx_strncmp(state_param.data, state_cookie.data, state_param.len) != 0)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "OIDC: State parameter mismatch or missing (CSRF check failed)");
                return NGX_HTTP_FORBIDDEN;
            }

            ngx_str_t code_key = ngx_string("code");
            ngx_str_t code_value;

            if (ngx_http_arg(r, code_key.data, code_key.len, &code_value) == NGX_OK) {
                return ngx_http_oidc_start_token_request(r, conf, &code_value);
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing code parameter in callback");
                return NGX_HTTP_BAD_REQUEST;
            }
        }

        /* Check for authentication via HMAC signed session cookie */
        ngx_uint_t i;
        ngx_list_part_t *part;
        ngx_table_elt_t *header;
        ngx_uint_t authenticated = 0;
        ngx_str_t auth_cookie = ngx_null_string;

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                header = part->elts;
                i = 0;
            }
            if (header[i].key.len == sizeof("Cookie") - 1 &&
                ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie", header[i].key.len) == 0) {

                u_char *p = header[i].value.data;
                u_char *end = p + header[i].value.len;
                while (p < end) {
                    if (end - p >= 10 && ngx_strncmp(p, "oidc_auth=", 10) == 0) {
                        p += 10;
                        auth_cookie.data = p;
                        while (p < end && *p != ';') {
                            p++;
                        }
                        auth_cookie.len = p - auth_cookie.data;
                        break;
                    }
                    while (p < end && *p != ';') p++;
                    if (p < end) p++;
                    while (p < end && *p == ' ') p++;
                }
                if (auth_cookie.data) {
                    break;
                }
            }
        }

        if (auth_cookie.data && auth_cookie.len > 64) {
            /* Verify HMAC: The cookie format is HMAC_HEX(64 bytes) + PAYLOAD */
            if (mcf && !mcf->secret_initialized) {
                if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) == 1) {
                    mcf->secret_initialized = 1;
                }
            }
            if (mcf && mcf->secret_initialized) {
                u_char expected_mac[32];
                u_char expected_mac_hex[64];
                unsigned int mac_len = 0;

                HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
                     auth_cookie.data + 64, auth_cookie.len - 64,
                     expected_mac, &mac_len);

                ngx_hex_dump(expected_mac_hex, expected_mac, 32);

                if (ngx_strncmp(auth_cookie.data, expected_mac_hex, 64) == 0) {
                    authenticated = 1;
                    /* Extract sub claim from payload for variable access */
                    u_char *payload = auth_cookie.data + 64;
                    u_char *colon = (u_char *)ngx_strchr(payload, ':');
                    if (colon) {
                        ctx->claims.sub.len = colon - payload;
                        ctx->claims.sub.data = ngx_palloc(r->pool, ctx->claims.sub.len);
                        if (ctx->claims.sub.data) {
                            ngx_memcpy(ctx->claims.sub.data, payload, ctx->claims.sub.len);
                        }
                    }
                }
            }
        }

        if (!authenticated) {
            /* Unauthenticated, perform redirect */
            return ngx_http_oidc_redirect_to_idp(r, conf, ctx);
        }
    }

    /* Proceed with normal processing */
    return NGX_DECLINED;
}

static ngx_int_t ngx_http_oidc_sub_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx && ctx->claims.sub.len > 0) {
        v->len = ctx->claims.sub.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->claims.sub.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_oidc_email_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx && ctx->claims.email.len > 0) {
        v->len = ctx->claims.email.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->claims.email.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_oidc_name_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx && ctx->claims.name.len > 0) {
        v->len = ctx->claims.name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->claims.name.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

/*
 * Post-configuration init function
 */
static ngx_int_t ngx_http_oidc_init(ngx_conf_t *cf) {
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_t        *var;

    ngx_str_t sub_name = ngx_string("oidc_claim_sub");
    var = ngx_http_add_variable(cf, &sub_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_sub_variable;
    var->data = 0;

    ngx_str_t email_name = ngx_string("oidc_claim_email");
    var = ngx_http_add_variable(cf, &email_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_email_variable;
    var->data = 0;

    ngx_str_t name_name = ngx_string("oidc_claim_name");
    var = ngx_http_add_variable(cf, &name_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_name_variable;
    var->data = 0;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oidc_access_handler;

    return NGX_OK;
}

static void *ngx_http_oidc_create_main_conf(ngx_conf_t *cf) {
    ngx_http_oidc_main_conf_t *mcf;
    mcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_main_conf_t));
    if (mcf == NULL) {
        return NULL;
    }
    return mcf;
}

/*
 * Module Context
 */
static ngx_http_module_t ngx_http_oidc_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_oidc_init,                    /* postconfiguration */

    ngx_http_oidc_create_main_conf,        /* create main configuration */
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
