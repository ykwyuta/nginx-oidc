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
} ngx_http_oidc_loc_conf_t;

/*
 * Request Context Structure
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    ngx_uint_t discovery_attempted:1;
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

    ngx_null_command
};

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

    /* Proceed with normal processing if metadata is already loaded */
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
