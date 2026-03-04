#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>

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
 */
typedef struct {
    ngx_str_t    auth_oidc;       /* Expected to hold the OIDC configuration name or switch */
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
    u_char *json_data = NULL;
    size_t json_len = 0;

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery request failed, status: %ui", r->headers_out.status);
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
        if (ctx->metadata == NULL) {
            ctx->metadata = ngx_pcalloc(r->parent->pool, sizeof(ngx_http_oidc_provider_metadata_t));
        }

        if (ctx->metadata) {
            if (ngx_http_oidc_parse_discovery_json(r->parent, json_data, json_len, ctx->metadata) == NGX_OK) {
                ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: Discovery successful");
            }
        }
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
        metadata->authorization_endpoint.data = ngx_palloc(r->pool, metadata->authorization_endpoint.len + 1);
        if (metadata->authorization_endpoint.data) {
            ngx_memcpy(metadata->authorization_endpoint.data, val, metadata->authorization_endpoint.len);
            metadata->authorization_endpoint.data[metadata->authorization_endpoint.len] = '\0';
        }
    }

    json_t *token_end = json_object_get(root, "token_endpoint");
    if (json_is_string(token_end)) {
        const char *val = json_string_value(token_end);
        metadata->token_endpoint.len = ngx_strlen(val);
        metadata->token_endpoint.data = ngx_palloc(r->pool, metadata->token_endpoint.len + 1);
        if (metadata->token_endpoint.data) {
            ngx_memcpy(metadata->token_endpoint.data, val, metadata->token_endpoint.len);
            metadata->token_endpoint.data[metadata->token_endpoint.len] = '\0';
        }
    }

    json_t *jwks_uri = json_object_get(root, "jwks_uri");
    if (json_is_string(jwks_uri)) {
        const char *val = json_string_value(jwks_uri);
        metadata->jwks_uri.len = ngx_strlen(val);
        metadata->jwks_uri.data = ngx_palloc(r->pool, metadata->jwks_uri.len + 1);
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

    return conf;
}

/*
 * Configuration merging function
 */
static char *ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->auth_oidc, prev->auth_oidc, "");
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
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
static ngx_int_t ngx_http_oidc_token_handler(ngx_http_request_t *r, void *data, ngx_int_t rc) {
    /* For Phase 3, we simply parse the JSON and check for token presence.
     * Actual JWT validation is Phase 4. */
    u_char *json_data = NULL;
    size_t json_len = 0;

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
                    /* In Phase 4 we will validate this token and set a cookie.
                     * For now, just assume success. */
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
        /* Set a flag to avoid infinite loops if needed, but here we just pass the request to the next phase
           or finalize it. For now, since Phase 3 doesn't actually set a session, we redirect to /
           or let the core run phases. To keep it simple and not hang: */
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
    ngx_str_t *auth_endpoint = &ctx->metadata->authorization_endpoint;
    u_char *p;
    size_t len;

    /* Simple state and nonce for now (Phase 3 requirements) */
    ngx_str_t state = ngx_string("random_state_123");
    ngx_str_t nonce = ngx_string("random_nonce_123");

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

    return NGX_HTTP_MOVED_TEMPORARILY;
}

/*
 * Access Phase Handler
 */
static ngx_int_t ngx_http_oidc_access_handler(ngx_http_request_t *r) {
    ngx_http_oidc_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    ngx_http_oidc_ctx_t *ctx;

    if (conf->auth_oidc.len == 0 || ngx_strncmp(conf->auth_oidc.data, "off", 3) == 0) {
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

    if (conf->oidc_provider.len > 0 && ctx->metadata == NULL) {
        if (ctx->discovery_attempted) {
            /* Discovery failed, do not retry */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery failed previously");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /* Metadata not loaded yet, initiate discovery */
        return ngx_http_oidc_start_discovery(r, conf);
    }

    /* If metadata is loaded, check for authentication */
    if (ctx->metadata != NULL) {
        /* Check if this is the callback path */
        if (conf->redirect_uri.len > 0 && r->uri.len >= conf->redirect_uri.len &&
            ngx_strncmp(r->uri.data, conf->redirect_uri.data, conf->redirect_uri.len) == 0) {

            if (ctx->token_attempted) {
                /* We already attempted the token request and the phase is running again.
                 * To avoid infinite loop, we must decline here or assume authentication
                 * state from phase 4 logic (which is not fully implemented yet).
                 * For now, just allow it to proceed to avoid hanging. */
                return NGX_DECLINED;
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

        /* Dummy check for authentication (e.g., check cookie)
         * For Phase 3, we simply assume unauthenticated and redirect
         * if no dummy "oidc_auth" cookie is found. */
        ngx_uint_t i;
        ngx_list_part_t *part;
        ngx_table_elt_t *header;
        ngx_uint_t authenticated = 0;

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
                if (ngx_strnstr(header[i].value.data, "oidc_auth=", header[i].value.len)) {
                    authenticated = 1;
                    break;
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

/*
 * Post-configuration init function
 */
static ngx_int_t ngx_http_oidc_init(ngx_conf_t *cf) {
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
