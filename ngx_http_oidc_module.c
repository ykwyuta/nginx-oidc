#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <jwt.h>

/*
 * Provider Metadata Structure
 */
typedef struct {
    ngx_str_t authorization_endpoint;
    ngx_str_t token_endpoint;
    ngx_str_t jwks_uri;
    ngx_str_t userinfo_endpoint;  /* UserInfo endpoint URL (optional) */
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
 * Key-value entry for arbitrary JWT claims ($oidc_claim_<name>)
 */
typedef struct {
    ngx_str_t key;
    ngx_str_t value;
} ngx_http_oidc_claim_entry_t;

/*
 * Main Configuration Structure (for caching)
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    time_t discovery_expires;
    u_char hmac_secret[32];
    ngx_uint_t secret_initialized:1;
    ngx_str_t cookie_secret;    /* configured shared secret for oidc_auth cookie HMAC */
    ngx_str_t discovery_url;    /* pre-built discovery URL for SSRF protection */
    ngx_str_t userinfo_url;     /* pre-built UserInfo URL for SSRF protection */
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
    ngx_str_t    oidc_scope;      /* OAuth scopes (default: "openid") */
    ngx_flag_t   oidc_use_userinfo;  /* call UserInfo endpoint after token (default: off) */
} ngx_http_oidc_loc_conf_t;

/*
 * Request Context Structure
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    ngx_uint_t discovery_attempted:1;
    ngx_uint_t token_attempted:1;
    ngx_uint_t userinfo_attempted:1;
    ngx_str_t id_token;
    ngx_str_t access_token;       /* stored for $oidc_access_token variable */
    ngx_http_oidc_claims_t claims;
    ngx_array_t *extra_claims;    /* arbitrary JWT claims for $oidc_claim_* prefix vars */
} ngx_http_oidc_ctx_t;

/* Forward declaration for ngx_http_oidc_module */
extern ngx_module_t ngx_http_oidc_module;

/* Forward declaration for JSON Parser */
static ngx_int_t ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r, const u_char *data, size_t len, ngx_http_oidc_provider_metadata_t *metadata);

/*
 * Base64URL encode (RFC 4648 §5, no padding).
 * dst must have capacity of at least ceil(len * 4 / 3) bytes.
 * Returns number of bytes written.
 */
static size_t
ngx_http_oidc_base64url_encode(u_char *dst, const u_char *src, size_t len)
{
    static const u_char enc[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    u_char *p = dst;
    size_t  i;

    for (i = 0; i + 2 < len; i += 3) {
        *p++ = enc[src[i] >> 2];
        *p++ = enc[((src[i] & 0x03) << 4) | (src[i + 1] >> 4)];
        *p++ = enc[((src[i + 1] & 0x0f) << 2) | (src[i + 2] >> 6)];
        *p++ = enc[src[i + 2] & 0x3f];
    }

    if (i < len) {
        *p++ = enc[src[i] >> 2];
        if (i + 1 < len) {
            *p++ = enc[((src[i] & 0x03) << 4) | (src[i + 1] >> 4)];
            *p++ = enc[(src[i + 1] & 0x0f) << 2];
        } else {
            *p++ = enc[(src[i] & 0x03) << 4];
        }
    }

    return p - dst;
}

/*
 * Compute PKCE code_challenge = BASE64URL(SHA256(verifier)).
 * verifier_len: length of the verifier string.
 * dst must have capacity of at least 43 bytes (ceil(32*4/3)=43).
 * Returns number of bytes written.
 */
static size_t
ngx_http_oidc_pkce_challenge(u_char *dst, const u_char *verifier, size_t verifier_len)
{
    u_char hash[32];

    SHA256(verifier, verifier_len, hash);
    return ngx_http_oidc_base64url_encode(dst, hash, sizeof(hash));
}

/*
 * Cookie helper: search for a named cookie in request headers.
 * Returns NGX_OK and sets *value on success, NGX_DECLINED if not found.
 */
static ngx_int_t
ngx_http_oidc_get_cookie(ngx_http_request_t *r, const char *name,
    size_t name_len, ngx_str_t *value)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;
    u_char            prefix[64];
    size_t            prefix_len;

    prefix_len = name_len + 1; /* name + '=' */
    if (prefix_len > sizeof(prefix)) {
        return NGX_DECLINED;
    }

    ngx_memcpy(prefix, name, name_len);
    prefix[name_len] = '=';

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

        if (header[i].key.len != sizeof("Cookie") - 1 ||
            ngx_strncasecmp(header[i].key.data, (u_char *) "Cookie",
                            header[i].key.len) != 0)
        {
            continue;
        }

        u_char *p   = header[i].value.data;
        u_char *end = p + header[i].value.len;

        while (p < end) {
            if ((size_t)(end - p) >= prefix_len &&
                ngx_strncmp(p, prefix, prefix_len) == 0)
            {
                p += prefix_len;
                value->data = p;
                while (p < end && *p != ';') {
                    p++;
                }
                value->len = p - value->data;
                return NGX_OK;
            }
            while (p < end && *p != ';') p++;
            if (p < end) p++;
            while (p < end && *p == ' ') p++;
        }
    }

    return NGX_DECLINED;
}

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
        if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
        return NGX_ERROR;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery request returned no upstream buffer");
        if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
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
                mcf->discovery_expires = ngx_time() + 3600;
                ctx->metadata = mcf->metadata;

                /* Cache userinfo URL for $oidc_userinfo_url variable (SSRF protection) */
                if (mcf->metadata->userinfo_endpoint.len > 0 && mcf->userinfo_url.len == 0) {
                    mcf->userinfo_url.data = ngx_palloc(ngx_cycle->pool,
                                                         mcf->metadata->userinfo_endpoint.len + 1);
                    if (mcf->userinfo_url.data) {
                        ngx_memcpy(mcf->userinfo_url.data,
                                   mcf->metadata->userinfo_endpoint.data,
                                   mcf->metadata->userinfo_endpoint.len);
                        mcf->userinfo_url.data[mcf->metadata->userinfo_endpoint.len] = '\0';
                        mcf->userinfo_url.len = mcf->metadata->userinfo_endpoint.len;
                    }
                }
            } else {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Failed to parse discovery json");
                mcf->metadata = NULL;
                if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
                return NGX_ERROR;
            }
        }
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Discovery request returned no data");
        if (r->parent) r->parent->write_event_handler = ngx_http_core_run_phases;
        return NGX_ERROR;
    }

    /* Resume the main request */
    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

/*
 * Start Discovery Subrequest.
 *
 * The full discovery URL is stored in mcf->discovery_url (ngx_cycle->pool)
 * so that the $oidc_discovery_url NGINX variable can expose it for use as
 * proxy_pass target in the internal /_oidc_discovery location, eliminating
 * the need for proxy_pass $arg_url (SSRF mitigation, issue 7).
 *
 * The URL is still passed as ?url=... args for backwards compatibility with
 * existing nginx.conf configurations.
 */
static ngx_int_t ngx_http_oidc_start_discovery(ngx_http_request_t *r, ngx_http_oidc_loc_conf_t *conf) {
    ngx_http_request_t *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    ngx_str_t discovery_uri = ngx_string("/_oidc_discovery");
    ngx_str_t discovery_args;
    const char *discovery_path = "/.well-known/openid-configuration";
    size_t url_len = conf->oidc_provider.len + ngx_strlen(discovery_path);

    /*
     * Store the pre-built discovery URL in main conf for the
     * $oidc_discovery_url variable (SSRF protection).
     */
    if (mcf && mcf->discovery_url.len == 0) {
        mcf->discovery_url.data = ngx_palloc(ngx_cycle->pool, url_len + 1);
        if (mcf->discovery_url.data) {
            mcf->discovery_url.len = ngx_snprintf(mcf->discovery_url.data,
                                                   url_len + 1, "%V%s",
                                                   &conf->oidc_provider,
                                                   discovery_path)
                                     - mcf->discovery_url.data;
        }
    }

    /* Build ?url=... args for backwards-compatible nginx.conf proxy_pass $arg_url */
    size_t args_len = sizeof("url=") - 1 + url_len;
    discovery_args.data = ngx_palloc(r->pool, args_len + 1);
    if (discovery_args.data == NULL) {
        return NGX_ERROR;
    }
    discovery_args.len = ngx_snprintf(discovery_args.data, args_len + 1,
                                      "url=%V%s",
                                      &conf->oidc_provider,
                                      discovery_path) - discovery_args.data;

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

    json_t *userinfo_end = json_object_get(root, "userinfo_endpoint");
    if (json_is_string(userinfo_end)) {
        const char *val = json_string_value(userinfo_end);
        metadata->userinfo_endpoint.len = ngx_strlen(val);
        metadata->userinfo_endpoint.data = ngx_palloc(ngx_cycle->pool,
                                                       metadata->userinfo_endpoint.len + 1);
        if (metadata->userinfo_endpoint.data) {
            ngx_memcpy(metadata->userinfo_endpoint.data, val, metadata->userinfo_endpoint.len);
            metadata->userinfo_endpoint.data[metadata->userinfo_endpoint.len] = '\0';
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
    conf->oidc_use_userinfo = NGX_CONF_UNSET;

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
    ngx_conf_merge_str_value(conf->oidc_scope, prev->oidc_scope, "openid");
    ngx_conf_merge_value(conf->oidc_use_userinfo, prev->oidc_use_userinfo, 0);

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

    /*
     * oidc_scope <scope>
     *
     * Space-separated list of OAuth 2.0 scopes to request.
     * Defaults to "openid".  Common values: "openid profile email".
     */
    { ngx_string("oidc_scope"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_scope),
      NULL },

    /*
     * oidc_cookie_secret <secret>
     *
     * Sets a fixed HMAC secret shared across all worker processes.
     * Without this directive each worker generates its own random secret,
     * causing oidc_auth cookies issued by one worker to fail verification
     * on another worker.  Set this to a long, random string in production.
     */
    { ngx_string("oidc_cookie_secret"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_oidc_main_conf_t, cookie_secret),
      NULL },

    /*
     * oidc_use_userinfo on|off
     *
     * When enabled, the module calls the UserInfo endpoint (from the
     * discovery document) using the access_token after JWT verification.
     * The UserInfo response is merged into the claims available via
     * $oidc_claim_* variables and is persisted in the session cookie so
     * that arbitrary claims (e.g. groups, roles) remain available on
     * subsequent requests.
     *
     * This is required for IdPs (Google, Microsoft Azure AD) that return
     * only minimal claims in the ID token itself.
     * Default: off
     */
    { ngx_string("oidc_use_userinfo"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_use_userinfo),
      NULL },

    ngx_null_command
};

static ngx_int_t ngx_http_oidc_start_jwks_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_start_userinfo_request(ngx_http_request_t *r);
static void ngx_http_oidc_issue_session_and_redirect(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf);

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

                /* id_token is mandatory; access_token is optional (some IdPs omit it) */
                if (json_is_string(id_token)) {
                    ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "OIDC: Successfully retrieved id_token");

                    const char *id_token_val = json_string_value(id_token);
                    ctx->id_token.len = ngx_strlen(id_token_val);
                    ctx->id_token.data = ngx_palloc(r->parent->pool, ctx->id_token.len + 1);
                    if (ctx->id_token.data) {
                        ngx_memcpy(ctx->id_token.data, id_token_val, ctx->id_token.len);
                        ctx->id_token.data[ctx->id_token.len] = '\0';
                    }

                    /* Store access_token when present for $oidc_access_token variable */
                    if (json_is_string(access_token)) {
                        const char *at_val = json_string_value(access_token);
                        ctx->access_token.len = ngx_strlen(at_val);
                        ctx->access_token.data = ngx_palloc(r->parent->pool,
                                                             ctx->access_token.len + 1);
                        if (ctx->access_token.data) {
                            ngx_memcpy(ctx->access_token.data, at_val, ctx->access_token.len);
                            ctx->access_token.data[ctx->access_token.len] = '\0';
                        }
                    }

                    if (ctx->id_token.data) {
                        json_decref(root);

                        /* Start JWKS subrequest */
                        return ngx_http_oidc_start_jwks_request(r->parent);
                    }
                } else {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing id_token in token response");
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
                ngx_http_oidc_get_cookie(r->parent, "oidc_nonce",
                                         sizeof("oidc_nonce") - 1, &nonce_cookie);

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

                    /*
                     * Extract all JWT grants into extra_claims so that any
                     * $oidc_claim_<name> variable is accessible during this
                     * request (e.g. groups, roles, tenant_id).
                     *
                     * Note: extra_claims is only populated on the initial
                     * authentication request.  Subsequent requests rely on the
                     * oidc_auth session cookie which carries only sub/email/name.
                     */
                    {
                        char *grants_json = jwt_get_grants_json(jwt, NULL);
                        if (grants_json != NULL) {
                            json_error_t jerr;
                            json_t *grants = json_loads(grants_json, 0, &jerr);
                            free(grants_json);
                            if (grants && json_is_object(grants)) {
                                const char *gkey;
                                json_t *gval;
                                ctx->extra_claims = ngx_array_create(r->parent->pool, 8,
                                                        sizeof(ngx_http_oidc_claim_entry_t));
                                if (ctx->extra_claims != NULL) {
                                    json_object_foreach(grants, gkey, gval) {
                                        const char *str_val = NULL;
                                        char num_buf[32];
                                        if (json_is_string(gval)) {
                                            str_val = json_string_value(gval);
                                        } else if (json_is_integer(gval)) {
                                            ngx_snprintf((u_char *) num_buf, sizeof(num_buf),
                                                         "%l%Z",
                                                         (long) json_integer_value(gval));
                                            str_val = num_buf;
                                        }
                                        if (str_val) {
                                            ngx_http_oidc_claim_entry_t *entry =
                                                ngx_array_push(ctx->extra_claims);
                                            if (entry) {
                                                size_t klen = ngx_strlen(gkey);
                                                size_t vlen = ngx_strlen(str_val);
                                                entry->key.data = ngx_palloc(r->parent->pool, klen);
                                                entry->key.len  = klen;
                                                entry->value.data = ngx_palloc(r->parent->pool, vlen);
                                                entry->value.len  = vlen;
                                                if (entry->key.data && entry->value.data) {
                                                    ngx_memcpy(entry->key.data, gkey, klen);
                                                    ngx_memcpy(entry->value.data, str_val, vlen);
                                                }
                                            }
                                        }
                                    }
                                }
                                json_decref(grants);
                            }
                        }
                    }

                    /*
                     * Issue session cookie and redirect.
                     * If oidc_use_userinfo is enabled and we have an access_token,
                     * delegate to the UserInfo subrequest first so that any extra
                     * claims returned by the IdP's UserInfo endpoint are merged into
                     * the session cookie before it is issued.
                     */
                    {
                        ngx_http_oidc_loc_conf_t *lcf_ui =
                            ngx_http_get_module_loc_conf(r->parent, ngx_http_oidc_module);
                        ngx_http_oidc_main_conf_t *mcf_ui =
                            ngx_http_get_module_main_conf(r->parent, ngx_http_oidc_module);

                        if (lcf_ui->oidc_use_userinfo == 1
                            && ctx->access_token.len > 0
                            && ctx->metadata != NULL
                            && ctx->metadata->userinfo_endpoint.len > 0)
                        {
                            jwt_free(jwt);
                            if (ngx_http_oidc_start_userinfo_request(r->parent) == NGX_OK) {
                                /* UserInfo handler will issue cookie and resume parent */
                                return NGX_OK;
                            }
                            /* Fallback: issue cookie without UserInfo */
                            ngx_http_oidc_issue_session_and_redirect(r->parent, ctx, mcf_ui);
                            if (r->parent) {
                                r->parent->write_event_handler = ngx_http_core_run_phases;
                            }
                            return NGX_OK;
                        }

                        ngx_http_oidc_issue_session_and_redirect(r->parent, ctx, mcf_ui);
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
 * Issue HMAC-signed session cookie and 302 redirect to the original URI.
 *
 * Cookie payload format:
 *   B64(sub):B64(email):B64(name):timestamp[|B64(key1):B64(val1)|B64(key2):B64(val2)...]
 *
 * The three fixed claims (sub/email/name) are always written first using
 * standard Base64 with ':' as separator (issue 11 fix).  Arbitrary JWT
 * claims from extra_claims are appended after a '|' delimiter, each as
 * B64(key):B64(val) pairs separated by '|'.  The total payload is capped
 * at OIDC_SESSION_MAX_PAYLOAD bytes so that the cookie stays within the
 * browser's 4096-byte cookie limit.
 */
#define OIDC_SESSION_MAX_PAYLOAD 3500

static void
ngx_http_oidc_issue_session_and_redirect(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf)
{
    if (mcf == NULL || !mcf->secret_initialized) {
        return;
    }

    u_char *p;

    /* --- Base64-encode fixed claims --- */
    ngx_str_t sub_b64, email_b64, name_b64;

    sub_b64.len   = ((ctx->claims.sub.len   + 2) / 3) * 4;
    email_b64.len = ((ctx->claims.email.len + 2) / 3) * 4;
    name_b64.len  = ((ctx->claims.name.len  + 2) / 3) * 4;

    sub_b64.data   = ngx_palloc(r->pool, sub_b64.len   + 1);
    email_b64.data = ngx_palloc(r->pool, email_b64.len + 1);
    name_b64.data  = ngx_palloc(r->pool, name_b64.len  + 1);

    if (sub_b64.data == NULL || email_b64.data == NULL || name_b64.data == NULL) {
        return;
    }

    ngx_encode_base64(&sub_b64,   &ctx->claims.sub);
    ngx_encode_base64(&email_b64, &ctx->claims.email);
    ngx_encode_base64(&name_b64,  &ctx->claims.name);

    /* --- Calculate base payload length: B64(sub):B64(email):B64(name):timestamp --- */
    size_t base_len = sub_b64.len + 1 + email_b64.len + 1 + name_b64.len + 1 + 20;
    /* 20 bytes is sufficient for a Unix timestamp */

    /* --- Calculate extra claims length --- */
    size_t extra_len = 0;
    if (ctx->extra_claims != NULL) {
        ngx_http_oidc_claim_entry_t *entries = ctx->extra_claims->elts;
        ngx_uint_t i;
        for (i = 0; i < ctx->extra_claims->nelts; i++) {
            size_t klen = ((entries[i].key.len   + 2) / 3) * 4;
            size_t vlen = ((entries[i].value.len + 2) / 3) * 4;
            size_t entry_len = 1 + klen + 1 + vlen; /* |B64(key):B64(val) */
            if (base_len + extra_len + entry_len > OIDC_SESSION_MAX_PAYLOAD) {
                break;
            }
            extra_len += entry_len;
        }
    }

    size_t payload_max = base_len + extra_len + 1; /* +1 for NUL */
    u_char *payload_buf = ngx_palloc(r->pool, payload_max);
    if (payload_buf == NULL) {
        return;
    }

    /* Write base payload */
    p = payload_buf;
    p = ngx_snprintf(p, base_len + 1, "%V:%V:%V:%T",
                     &sub_b64, &email_b64, &name_b64, ngx_time());

    /* Append extra claims: |B64(key):B64(val) */
    if (ctx->extra_claims != NULL) {
        ngx_http_oidc_claim_entry_t *entries = ctx->extra_claims->elts;
        ngx_uint_t i;
        size_t written_extra = 0;
        for (i = 0; i < ctx->extra_claims->nelts; i++) {
            size_t klen = ((entries[i].key.len   + 2) / 3) * 4;
            size_t vlen = ((entries[i].value.len + 2) / 3) * 4;
            size_t entry_len = 1 + klen + 1 + vlen;
            if (written_extra + entry_len > extra_len) {
                break;
            }

            ngx_str_t kb64 = { klen, ngx_palloc(r->pool, klen + 1) };
            ngx_str_t vb64 = { vlen, ngx_palloc(r->pool, vlen + 1) };
            if (kb64.data == NULL || vb64.data == NULL) {
                break;
            }

            ngx_encode_base64(&kb64, &entries[i].key);
            ngx_encode_base64(&vb64, &entries[i].value);

            *p++ = '|';
            p = ngx_cpymem(p, kb64.data, kb64.len);
            *p++ = ':';
            p = ngx_cpymem(p, vb64.data, vb64.len);
            written_extra += entry_len;
        }
    }

    size_t payload_len = p - payload_buf;

    /* --- HMAC-SHA256 sign --- */
    u_char mac[32];
    u_char mac_hex[64];
    unsigned int mac_len_out = 0;

    HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
         payload_buf, payload_len, mac, &mac_len_out);
    ngx_hex_dump(mac_hex, mac, 32);

    /* --- Set oidc_auth cookie --- */
    ngx_table_elt_t *set_cookie_auth = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_auth) {
        set_cookie_auth->hash = 1;
        ngx_str_set(&set_cookie_auth->key, "Set-Cookie");
        set_cookie_auth->value.len = sizeof("oidc_auth=") - 1 + 64 + payload_len
                                   + sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1;
        set_cookie_auth->value.data = ngx_pnalloc(r->pool, set_cookie_auth->value.len);
        if (set_cookie_auth->value.data) {
            p = set_cookie_auth->value.data;
            p = ngx_cpymem(p, "oidc_auth=", sizeof("oidc_auth=") - 1);
            p = ngx_cpymem(p, mac_hex, 64);
            p = ngx_cpymem(p, payload_buf, payload_len);
            p = ngx_cpymem(p, "; HttpOnly; Secure; SameSite=Lax; Path=/",
                           sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1);
        }
    }

    /* --- Clear OIDC temporary cookies --- */
    ngx_table_elt_t *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        h->hash = 1;
        ngx_str_set(&h->key, "Set-Cookie");
        ngx_str_set(&h->value, "oidc_state=; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"
                               " Secure; SameSite=Lax; Path=/");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        h->hash = 1;
        ngx_str_set(&h->key, "Set-Cookie");
        ngx_str_set(&h->value, "oidc_nonce=; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"
                               " Secure; SameSite=Lax; Path=/");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        h->hash = 1;
        ngx_str_set(&h->key, "Set-Cookie");
        ngx_str_set(&h->value, "oidc_return_to=; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"
                               " Secure; SameSite=Lax; Path=/");
    }

    h = ngx_list_push(&r->headers_out.headers);
    if (h) {
        h->hash = 1;
        ngx_str_set(&h->key, "Set-Cookie");
        ngx_str_set(&h->value, "oidc_pkce_verifier=; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"
                               " Secure; SameSite=Lax; Path=/");
    }

    /* --- 302 redirect to original URI --- */
    ngx_table_elt_t *location = ngx_list_push(&r->headers_out.headers);
    if (location) {
        location->hash = 1;
        ngx_str_set(&location->key, "Location");

        ngx_str_t return_to = ngx_null_string;
        ngx_http_oidc_get_cookie(r, "oidc_return_to",
                                 sizeof("oidc_return_to") - 1, &return_to);
        if (return_to.len > 0 && return_to.data[0] == '/') {
            location->value = return_to;
        } else {
            ngx_str_set(&location->value, "/");
        }

        r->headers_out.status = NGX_HTTP_MOVED_TEMPORARILY;
        r->headers_out.location = location;
    }
}

/*
 * UserInfo subrequest completion handler.
 *
 * Parses the IdP UserInfo JSON response and merges the returned claims into
 * ctx->extra_claims (and updates the fixed claims sub/email/name when
 * present).  Then issues the session cookie and redirects.
 */
static ngx_int_t
ngx_http_oidc_userinfo_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_oidc_ctx_t       *ctx = ngx_http_get_module_ctx(r->parent, ngx_http_oidc_module);
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r->parent, ngx_http_oidc_module);

    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: UserInfo request failed (status %ui), "
                      "proceeding with ID token claims only",
                      r->headers_out.status);
        /* Non-fatal: issue session with whatever claims we have */
        goto done;
    }

    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: UserInfo request returned no buffer");
        goto done;
    }

    {
        u_char *json_data;
        size_t  json_len;

        json_len  = r->upstream->buffer.last - r->upstream->buffer.pos;
        json_data = ngx_palloc(r->pool, json_len);
        if (json_data == NULL) {
            goto done;
        }
        ngx_memcpy(json_data, r->upstream->buffer.pos, json_len);

        json_error_t jerr;
        json_t *root = json_loadb((const char *) json_data, json_len, 0, &jerr);
        if (root == NULL || !json_is_object(root)) {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "OIDC: Failed to parse UserInfo JSON: %s", jerr.text);
            if (root) json_decref(root);
            goto done;
        }

        ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                      "OIDC: UserInfo response parsed successfully");

        /* Ensure extra_claims array exists */
        if (ctx->extra_claims == NULL) {
            ctx->extra_claims = ngx_array_create(r->parent->pool, 8,
                                    sizeof(ngx_http_oidc_claim_entry_t));
        }

        const char *ukey;
        json_t     *uval;
        json_object_foreach(root, ukey, uval) {
            const char *str_val = NULL;
            char num_buf[32];

            if (json_is_string(uval)) {
                str_val = json_string_value(uval);
            } else if (json_is_integer(uval)) {
                ngx_snprintf((u_char *) num_buf, sizeof(num_buf),
                             "%l%Z", (long) json_integer_value(uval));
                str_val = num_buf;
            }

            if (str_val == NULL) {
                continue;
            }

            /* Update fixed claims when UserInfo provides them */
            if (ngx_strcmp(ukey, "sub") == 0) {
                ctx->claims.sub.len  = ngx_strlen(str_val);
                ctx->claims.sub.data = ngx_palloc(r->parent->pool, ctx->claims.sub.len);
                if (ctx->claims.sub.data) {
                    ngx_memcpy(ctx->claims.sub.data, str_val, ctx->claims.sub.len);
                }
                continue;
            }
            if (ngx_strcmp(ukey, "email") == 0) {
                ctx->claims.email.len  = ngx_strlen(str_val);
                ctx->claims.email.data = ngx_palloc(r->parent->pool, ctx->claims.email.len);
                if (ctx->claims.email.data) {
                    ngx_memcpy(ctx->claims.email.data, str_val, ctx->claims.email.len);
                }
                continue;
            }
            if (ngx_strcmp(ukey, "name") == 0) {
                ctx->claims.name.len  = ngx_strlen(str_val);
                ctx->claims.name.data = ngx_palloc(r->parent->pool, ctx->claims.name.len);
                if (ctx->claims.name.data) {
                    ngx_memcpy(ctx->claims.name.data, str_val, ctx->claims.name.len);
                }
                continue;
            }

            /* Arbitrary claim: add/overwrite in extra_claims */
            if (ctx->extra_claims == NULL) {
                continue;
            }

            /* Check if this key already exists (from ID token) and overwrite */
            ngx_uint_t found = 0;
            ngx_http_oidc_claim_entry_t *entries = ctx->extra_claims->elts;
            ngx_uint_t ei;
            for (ei = 0; ei < ctx->extra_claims->nelts; ei++) {
                if (entries[ei].key.len == ngx_strlen(ukey)
                    && ngx_strncmp(entries[ei].key.data, ukey,
                                   entries[ei].key.len) == 0)
                {
                    size_t vlen = ngx_strlen(str_val);
                    entries[ei].value.data = ngx_palloc(r->parent->pool, vlen);
                    if (entries[ei].value.data) {
                        entries[ei].value.len = vlen;
                        ngx_memcpy(entries[ei].value.data, str_val, vlen);
                    }
                    found = 1;
                    break;
                }
            }
            if (!found) {
                ngx_http_oidc_claim_entry_t *entry = ngx_array_push(ctx->extra_claims);
                if (entry) {
                    size_t klen = ngx_strlen(ukey);
                    size_t vlen = ngx_strlen(str_val);
                    entry->key.data   = ngx_palloc(r->parent->pool, klen);
                    entry->key.len    = klen;
                    entry->value.data = ngx_palloc(r->parent->pool, vlen);
                    entry->value.len  = vlen;
                    if (entry->key.data && entry->value.data) {
                        ngx_memcpy(entry->key.data, ukey, klen);
                        ngx_memcpy(entry->value.data, str_val, vlen);
                    }
                }
            }
        }

        json_decref(root);
    }

done:
    ngx_http_oidc_issue_session_and_redirect(r->parent, ctx, mcf);

    if (r->parent) {
        r->parent->write_event_handler = ngx_http_core_run_phases;
    }

    return NGX_OK;
}

/*
 * Start UserInfo Subrequest.
 *
 * Issues a subrequest to /_oidc_userinfo with the access_token passed as
 * the ?token= query parameter.  The nginx.conf internal location should set:
 *
 *   proxy_pass $oidc_userinfo_url;
 *   proxy_set_header Authorization "Bearer $arg_token";
 *
 * The URL is pre-built from the discovery document and stored in
 * mcf->userinfo_url (SSRF protection, same pattern as $oidc_jwks_url).
 */
static ngx_int_t
ngx_http_oidc_start_userinfo_request(ngx_http_request_t *r)
{
    ngx_http_request_t        *sr;
    ngx_http_post_subrequest_t *psr;
    ngx_http_oidc_ctx_t       *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ngx_str_t  userinfo_uri  = ngx_string("/_oidc_userinfo");
    ngx_str_t  userinfo_args;
    size_t     token_enc_len;
    u_char    *p;

    if (ctx == NULL || ctx->access_token.len == 0) {
        return NGX_ERROR;
    }

    token_enc_len = ctx->access_token.len
                  + 2 * ngx_escape_uri(NULL, ctx->access_token.data,
                                       ctx->access_token.len, NGX_ESCAPE_ARGS);

    userinfo_args.data = ngx_palloc(r->pool, sizeof("token=") - 1 + token_enc_len + 1);
    if (userinfo_args.data == NULL) {
        return NGX_ERROR;
    }

    p = userinfo_args.data;
    p = ngx_cpymem(p, "token=", sizeof("token=") - 1);
    if (token_enc_len == ctx->access_token.len) {
        p = ngx_cpymem(p, ctx->access_token.data, ctx->access_token.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, ctx->access_token.data,
                                       ctx->access_token.len, NGX_ESCAPE_ARGS);
    }
    userinfo_args.len = p - userinfo_args.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_userinfo_handler;
    psr->data    = NULL;

    ctx->userinfo_attempted = 1;

    if (ngx_http_subrequest(r, &userinfo_uri, &userinfo_args, &sr,
                            psr, NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_ERROR;
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

    /* Read PKCE code_verifier from cookie (64 hex chars) */
    ngx_str_t pkce_verifier = ngx_null_string;
    ngx_http_oidc_get_cookie(r, "oidc_pkce_verifier",
                             sizeof("oidc_pkce_verifier") - 1, &pkce_verifier);

    size_t code_enc_len = code->len + 2 * ngx_escape_uri(NULL, code->data, code->len, NGX_ESCAPE_ARGS);
    size_t client_id_enc_len = conf->client_id.len + 2 * ngx_escape_uri(NULL, conf->client_id.data, conf->client_id.len, NGX_ESCAPE_ARGS);
    size_t client_secret_enc_len = conf->client_secret.len + 2 * ngx_escape_uri(NULL, conf->client_secret.data, conf->client_secret.len, NGX_ESCAPE_ARGS);
    size_t redirect_uri_enc_len = conf->redirect_uri.len + 2 * ngx_escape_uri(NULL, conf->redirect_uri.data, conf->redirect_uri.len, NGX_ESCAPE_ARGS);

    /* "code=&client_id=&client_secret=&redirect_uri=&grant_type=authorization_code
     *  [&code_verifier=...]" */
    size_t len = sizeof("code=") - 1 + code_enc_len
               + sizeof("&client_id=") - 1 + client_id_enc_len
               + sizeof("&client_secret=") - 1 + client_secret_enc_len
               + sizeof("&redirect_uri=") - 1 + redirect_uri_enc_len
               + sizeof("&grant_type=authorization_code") - 1
               + (pkce_verifier.len > 0
                  ? sizeof("&code_verifier=") - 1 + pkce_verifier.len
                  : 0);

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

    p = ngx_cpymem(p, "&grant_type=authorization_code",
                   sizeof("&grant_type=authorization_code") - 1);

    /* Append PKCE code_verifier when available */
    if (pkce_verifier.len > 0) {
        p = ngx_cpymem(p, "&code_verifier=", sizeof("&code_verifier=") - 1);
        p = ngx_cpymem(p, pkce_verifier.data, pkce_verifier.len);
    }

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
    size_t scope_enc_len = conf->oidc_scope.len + 2 * ngx_escape_uri(NULL, conf->oidc_scope.data, conf->oidc_scope.len, NGX_ESCAPE_ARGS);

    /* Calculate URL length:
     * auth_endpoint + "?response_type=code&scope=" + scope + "&client_id=" + client_id
     * + "&redirect_uri=" + redirect_uri + "&state=" + state + "&nonce=" + nonce
     * + "&code_challenge=" + challenge + "&code_challenge_method=S256"
     */
    len = auth_endpoint->len + sizeof("?response_type=code&scope=") - 1
        + scope_enc_len + sizeof("&client_id=") - 1 + client_id_enc_len
        + sizeof("&redirect_uri=") - 1 + redirect_uri_enc_len
        + sizeof("&state=") - 1 + state.len + sizeof("&nonce=") - 1 + nonce.len
        + sizeof("&code_challenge=") - 1 + 43 /* Base64URL(SHA256) = 43 chars */
        + sizeof("&code_challenge_method=S256") - 1;

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

    /*
     * Generate PKCE code_verifier (32 random bytes → 64 hex chars) and
     * compute code_challenge = BASE64URL(SHA256(verifier)) for S256 method.
     */
    u_char pkce_verifier_buf[32];
    u_char pkce_verifier_hex[64];
    u_char pkce_challenge[43];
    size_t pkce_challenge_len;

    if (RAND_bytes(pkce_verifier_buf, sizeof(pkce_verifier_buf)) != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: Failed to generate PKCE verifier");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_hex_dump(pkce_verifier_hex, pkce_verifier_buf, sizeof(pkce_verifier_buf));
    pkce_challenge_len = ngx_http_oidc_pkce_challenge(pkce_challenge,
                                                       pkce_verifier_hex,
                                                       sizeof(pkce_verifier_hex));

    p = location->value.data;
    p = ngx_cpymem(p, auth_endpoint->data, auth_endpoint->len);
    p = ngx_cpymem(p, "?response_type=code&scope=", sizeof("?response_type=code&scope=") - 1);
    if (scope_enc_len == conf->oidc_scope.len) {
        p = ngx_cpymem(p, conf->oidc_scope.data, conf->oidc_scope.len);
    } else {
        p = (u_char *) ngx_escape_uri(p, conf->oidc_scope.data, conf->oidc_scope.len, NGX_ESCAPE_ARGS);
    }
    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
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
    p = ngx_cpymem(p, "&code_challenge=", sizeof("&code_challenge=") - 1);
    p = ngx_cpymem(p, pkce_challenge, pkce_challenge_len);
    p = ngx_cpymem(p, "&code_challenge_method=S256",
                   sizeof("&code_challenge_method=S256") - 1);

    location->value.len = p - location->value.data;

    r->headers_out.location = location;

    /* Set Cookie for state */
    set_cookie_state = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_state == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    set_cookie_state->hash = 1;
    ngx_str_set(&set_cookie_state->key, "Set-Cookie");
    set_cookie_state->value.len = sizeof("oidc_state=") - 1 + state.len
                                + sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1;
    set_cookie_state->value.data = ngx_pnalloc(r->pool, set_cookie_state->value.len);
    if (set_cookie_state->value.data) {
        p = set_cookie_state->value.data;
        p = ngx_cpymem(p, "oidc_state=", sizeof("oidc_state=") - 1);
        p = ngx_cpymem(p, state.data, state.len);
        p = ngx_cpymem(p, "; HttpOnly; Secure; SameSite=Lax; Path=/",
                       sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1);
    }

    /* Set Cookie for nonce */
    set_cookie_nonce = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_nonce == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    set_cookie_nonce->hash = 1;
    ngx_str_set(&set_cookie_nonce->key, "Set-Cookie");
    set_cookie_nonce->value.len = sizeof("oidc_nonce=") - 1 + nonce.len
                                + sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1;
    set_cookie_nonce->value.data = ngx_pnalloc(r->pool, set_cookie_nonce->value.len);
    if (set_cookie_nonce->value.data) {
        p = set_cookie_nonce->value.data;
        p = ngx_cpymem(p, "oidc_nonce=", sizeof("oidc_nonce=") - 1);
        p = ngx_cpymem(p, nonce.data, nonce.len);
        p = ngx_cpymem(p, "; HttpOnly; Secure; SameSite=Lax; Path=/",
                       sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1);
    }

    /* Set Cookie for PKCE code_verifier (64 hex chars) */
    ngx_table_elt_t *set_cookie_pkce;
    set_cookie_pkce = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_pkce == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    set_cookie_pkce->hash = 1;
    ngx_str_set(&set_cookie_pkce->key, "Set-Cookie");
    set_cookie_pkce->value.len = sizeof("oidc_pkce_verifier=") - 1
                               + sizeof(pkce_verifier_hex)
                               + sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1;
    set_cookie_pkce->value.data = ngx_pnalloc(r->pool, set_cookie_pkce->value.len);
    if (set_cookie_pkce->value.data) {
        p = set_cookie_pkce->value.data;
        p = ngx_cpymem(p, "oidc_pkce_verifier=", sizeof("oidc_pkce_verifier=") - 1);
        p = ngx_cpymem(p, pkce_verifier_hex, sizeof(pkce_verifier_hex));
        p = ngx_cpymem(p, "; HttpOnly; Secure; SameSite=Lax; Path=/",
                       sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1);
        set_cookie_pkce->value.len = p - set_cookie_pkce->value.data;
    }

    /*
     * Save original request URI (including query string) so we can redirect
     * there after authentication.  Limit to 2048 bytes to stay within cookie
     * size limits (cookie overhead is ~80 bytes, leaving plenty of margin).
     */
    ngx_table_elt_t *set_cookie_return_to;
    set_cookie_return_to = ngx_list_push(&r->headers_out.headers);
    if (set_cookie_return_to != NULL) {
        /* Build "path?query" string, then trim to 2048 bytes if necessary */
        size_t full_len = r->uri.len
                        + (r->args.len > 0 ? 1 + r->args.len : 0); /* '?' + args */
        size_t uri_len = full_len > 2048 ? 2048 : full_len;

        set_cookie_return_to->hash = 1;
        ngx_str_set(&set_cookie_return_to->key, "Set-Cookie");
        set_cookie_return_to->value.len = sizeof("oidc_return_to=") - 1 + uri_len
                                        + sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1;
        set_cookie_return_to->value.data = ngx_pnalloc(r->pool,
                                                        set_cookie_return_to->value.len);
        if (set_cookie_return_to->value.data) {
            p = set_cookie_return_to->value.data;
            p = ngx_cpymem(p, "oidc_return_to=", sizeof("oidc_return_to=") - 1);
            /* Copy as much of the URI as fits within the 2048-byte budget */
            if (r->uri.len <= uri_len) {
                p = ngx_cpymem(p, r->uri.data, r->uri.len);
                if (r->args.len > 0 && uri_len > r->uri.len) {
                    size_t args_copy = uri_len - r->uri.len - 1; /* -1 for '?' */
                    if (args_copy > 0) {
                        *p++ = '?';
                        p = ngx_cpymem(p, r->args.data,
                                       args_copy < r->args.len ? args_copy : r->args.len);
                    }
                }
            } else {
                p = ngx_cpymem(p, r->uri.data, uri_len);
            }
            p = ngx_cpymem(p, "; HttpOnly; Secure; SameSite=Lax; Path=/",
                           sizeof("; HttpOnly; Secure; SameSite=Lax; Path=/") - 1);
            /* Fix up the value length to reflect what was actually written */
            set_cookie_return_to->value.len = p - set_cookie_return_to->value.data;
        }
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
        /* Invalidate cached metadata if TTL has expired */
        if (ngx_time() > mcf->discovery_expires) {
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                          "OIDC: Discovery cache expired, re-fetching");
            mcf->metadata = NULL;
            mcf->discovery_expires = 0;
        } else {
            ctx->metadata = mcf->metadata;
        }
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

            ngx_str_t code_key = ngx_string("code");
            ngx_str_t code_value;
            ngx_str_t state_key = ngx_string("state");
            ngx_str_t state_value;

            if (ngx_http_arg(r, code_key.data, code_key.len, &code_value) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing code parameter in callback");
                return NGX_HTTP_BAD_REQUEST;
            }

            if (ngx_http_arg(r, state_key.data, state_key.len, &state_value) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: Missing state parameter in callback");
                return NGX_HTTP_BAD_REQUEST;
            }

            /* Verify state against oidc_state cookie */
            ngx_str_t state_cookie = ngx_null_string;
            ngx_http_oidc_get_cookie(r, "oidc_state", sizeof("oidc_state") - 1,
                                     &state_cookie);

            if (state_cookie.data == NULL || state_value.len != state_cookie.len ||
                ngx_strncmp(state_value.data, state_cookie.data, state_cookie.len) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "OIDC: State mismatch or missing in callback");
                return NGX_HTTP_FORBIDDEN;
            }

            return ngx_http_oidc_start_token_request(r, conf, &code_value);
        }

        /* Check for authentication via HMAC signed session cookie */
        ngx_uint_t authenticated = 0;
        ngx_str_t auth_cookie = ngx_null_string;

        ngx_http_oidc_get_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1, &auth_cookie);

        if (auth_cookie.data && auth_cookie.len > 64) {
            /* Verify HMAC: cookie format is HMAC_HEX(64 chars) + PAYLOAD */
            if (mcf && mcf->secret_initialized) {
                u_char expected_mac[32];
                u_char expected_mac_hex[64];
                unsigned int mac_len = 0;

                HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
                     auth_cookie.data + 64, auth_cookie.len - 64,
                     expected_mac, &mac_len);

                ngx_hex_dump(expected_mac_hex, expected_mac, 32);

                /* Use constant-time comparison to prevent timing attacks */
                if (CRYPTO_memcmp(auth_cookie.data, expected_mac_hex, 64) == 0) {
                    authenticated = 1;

                    /*
                     * Extract claims from payload: B64(sub):B64(email):B64(name):timestamp
                     * Each claim is Base64-encoded so ':' inside a value is safe (issue 11).
                     * Restore all three claims for variable access in this request.
                     */
                    u_char *pl     = auth_cookie.data + 64;
                    u_char *pl_end = auth_cookie.data + auth_cookie.len;

                    u_char *c1 = ngx_strlchr(pl, pl_end, ':');
                    if (c1) {
                        ngx_str_t enc;
                        ngx_str_t dec;

                        enc.data = pl;
                        enc.len  = c1 - pl;
                        dec.data = ngx_palloc(r->pool, enc.len + 1);
                        if (dec.data) {
                            dec.len = enc.len;
                            if (ngx_decode_base64(&dec, &enc) == NGX_OK) {
                                ctx->claims.sub = dec;
                            }
                        }

                        u_char *c2 = ngx_strlchr(c1 + 1, pl_end, ':');
                        if (c2) {
                            enc.data = c1 + 1;
                            enc.len  = c2 - (c1 + 1);
                            dec.data = ngx_palloc(r->pool, enc.len + 1);
                            if (dec.data) {
                                dec.len = enc.len;
                                if (ngx_decode_base64(&dec, &enc) == NGX_OK) {
                                    ctx->claims.email = dec;
                                }
                            }

                            u_char *c3 = ngx_strlchr(c2 + 1, pl_end, ':');
                            if (c3) {
                                enc.data = c2 + 1;
                                enc.len  = c3 - (c2 + 1);
                                dec.data = ngx_palloc(r->pool, enc.len + 1);
                                if (dec.data) {
                                    dec.len = enc.len;
                                    if (ngx_decode_base64(&dec, &enc) == NGX_OK) {
                                        ctx->claims.name = dec;
                                    }
                                }

                                /*
                                 * Restore arbitrary claims persisted in the cookie.
                                 * Format after the timestamp field: |B64(key):B64(val)|...
                                 * The '|' sentinel separates the base claims section
                                 * (sub:email:name:timestamp) from the extra claims section.
                                 */
                                u_char *pipe = ngx_strlchr(c3 + 1, pl_end, '|');
                                if (pipe != NULL) {
                                    u_char *ep = pipe + 1;
                                    while (ep < pl_end) {
                                        u_char *next_pipe = ngx_strlchr(ep, pl_end, '|');
                                        u_char *claim_end = next_pipe ? next_pipe : pl_end;
                                        u_char *colon     = ngx_strlchr(ep, claim_end, ':');
                                        if (colon) {
                                            ngx_str_t kenc_e = { colon - ep, ep };
                                            ngx_str_t venc_e = { claim_end - (colon + 1), colon + 1 };
                                            ngx_str_t kdec_e, vdec_e;

                                            kdec_e.data = ngx_palloc(r->pool, kenc_e.len + 1);
                                            kdec_e.len  = kenc_e.len;
                                            vdec_e.data = ngx_palloc(r->pool, venc_e.len + 1);
                                            vdec_e.len  = venc_e.len;

                                            if (kdec_e.data && vdec_e.data
                                                && ngx_decode_base64(&kdec_e, &kenc_e) == NGX_OK
                                                && ngx_decode_base64(&vdec_e, &venc_e) == NGX_OK)
                                            {
                                                if (ctx->extra_claims == NULL) {
                                                    ctx->extra_claims = ngx_array_create(
                                                        r->pool, 8,
                                                        sizeof(ngx_http_oidc_claim_entry_t));
                                                }
                                                if (ctx->extra_claims) {
                                                    ngx_http_oidc_claim_entry_t *entry =
                                                        ngx_array_push(ctx->extra_claims);
                                                    if (entry) {
                                                        entry->key   = kdec_e;
                                                        entry->value = vdec_e;
                                                    }
                                                }
                                            }
                                        }
                                        if (next_pipe == NULL) break;
                                        ep = next_pipe + 1;
                                    }
                                }
                            }
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

/*
 * Prefix variable handler for $oidc_claim_<name>.
 *
 * Handles all $oidc_claim_* variables through a single prefix handler.
 * For the fixed claims (sub, email, name) values are restored from the
 * oidc_auth session cookie on every request.  For arbitrary claims
 * (e.g. $oidc_claim_groups, $oidc_claim_roles) values are only available
 * during the initial authentication request when the JWT is verified;
 * they are NOT persisted in the session cookie.
 *
 * The NGINX prefix-variable mechanism sets data = (uintptr_t) &ngx_str_t
 * where the ngx_str_t holds the full variable name including the prefix.
 */
static ngx_int_t
ngx_http_oidc_claim_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t                    *varname = (ngx_str_t *) data;
    ngx_http_oidc_ctx_t          *ctx;
    ngx_str_t                     claim_name;
    ngx_str_t                    *claim_val = NULL;
    ngx_http_oidc_claim_entry_t  *entries;
    ngx_uint_t                    i;

    /* Strip the "oidc_claim_" prefix (11 chars) to obtain claim name */
    claim_name.data = varname->data + (sizeof("oidc_claim_") - 1);
    claim_name.len  = varname->len  - (sizeof("oidc_claim_") - 1);

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    /* Check the three fixed claims first (always available from session cookie) */
    if (claim_name.len == sizeof("sub") - 1
        && ngx_strncmp(claim_name.data, "sub", claim_name.len) == 0)
    {
        if (ctx->claims.sub.len > 0) {
            claim_val = &ctx->claims.sub;
        }
    } else if (claim_name.len == sizeof("email") - 1
               && ngx_strncmp(claim_name.data, "email", claim_name.len) == 0)
    {
        if (ctx->claims.email.len > 0) {
            claim_val = &ctx->claims.email;
        }
    } else if (claim_name.len == sizeof("name") - 1
               && ngx_strncmp(claim_name.data, "name", claim_name.len) == 0)
    {
        if (ctx->claims.name.len > 0) {
            claim_val = &ctx->claims.name;
        }
    } else {
        /* Search extra_claims for arbitrary JWT claims */
        if (ctx->extra_claims != NULL) {
            entries = ctx->extra_claims->elts;
            for (i = 0; i < ctx->extra_claims->nelts; i++) {
                if (entries[i].key.len == claim_name.len
                    && ngx_strncasecmp(entries[i].key.data,
                                       claim_name.data,
                                       claim_name.len) == 0)
                {
                    claim_val = &entries[i].value;
                    break;
                }
            }
        }
    }

    if (claim_val != NULL && claim_val->len > 0) {
        v->len         = claim_val->len;
        v->valid       = 1;
        v->no_cacheable = 0;
        v->not_found   = 0;
        v->data        = claim_val->data;
    } else {
        v->not_found = 1;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_oidc_access_token_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx && ctx->access_token.len > 0) {
        v->len = ctx->access_token.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->access_token.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

/*
 * $oidc_discovery_url — the pre-built IdP discovery URL derived from
 * oidc_provider config.  For use in nginx.conf proxy_pass to prevent SSRF
 * by eliminating the need for proxy_pass $arg_url (issue 7).
 */
static ngx_int_t ngx_http_oidc_discovery_url_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (mcf && mcf->discovery_url.len > 0) {
        v->len = mcf->discovery_url.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = mcf->discovery_url.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

/*
 * $oidc_jwks_url — the JWKS URI obtained from the IdP discovery document.
 * For use in nginx.conf proxy_pass instead of proxy_pass $arg_url (issue 7).
 */
static ngx_int_t ngx_http_oidc_jwks_url_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (mcf && mcf->metadata && mcf->metadata->jwks_uri.len > 0) {
        v->len = mcf->metadata->jwks_uri.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = mcf->metadata->jwks_uri.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

/*
 * $oidc_userinfo_url — the UserInfo URI obtained from the IdP discovery
 * document.  For use in nginx.conf proxy_pass for the /_oidc_userinfo
 * internal location (SSRF protection).
 */
static ngx_int_t
ngx_http_oidc_userinfo_url_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_main_conf_t *mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);
    if (mcf && mcf->userinfo_url.len > 0) {
        v->len         = mcf->userinfo_url.len;
        v->valid       = 1;
        v->no_cacheable = 0;
        v->not_found   = 0;
        v->data        = mcf->userinfo_url.data;
    } else {
        v->not_found = 1;
    }
    return NGX_OK;
}

/*
 * init_process: initialise the HMAC secret once per worker process.
 *
 * If oidc_cookie_secret is configured the same value is used in every
 * worker, so cookies remain valid regardless of which worker serves the
 * request.  Without it each worker falls back to a random secret (cookies
 * issued by worker A will not verify on worker B).
 */
static ngx_int_t
ngx_http_oidc_init_process(ngx_cycle_t *cycle)
{
    ngx_http_oidc_main_conf_t *mcf;

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_oidc_module);
    if (mcf == NULL) {
        return NGX_OK;
    }

    if (mcf->cookie_secret.len > 0) {
        /* Use configured shared secret */
        size_t secret_len = mcf->cookie_secret.len < sizeof(mcf->hmac_secret)
                            ? mcf->cookie_secret.len
                            : sizeof(mcf->hmac_secret);
        ngx_memzero(mcf->hmac_secret, sizeof(mcf->hmac_secret));
        ngx_memcpy(mcf->hmac_secret, mcf->cookie_secret.data, secret_len);
        mcf->secret_initialized = 1;
    } else {
        /* Fallback: per-worker random secret (sessions not portable across workers) */
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "oidc: oidc_cookie_secret not set; "
                      "each worker uses a random HMAC secret. "
                      "Set oidc_cookie_secret for multi-worker deployments.");
        if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) != 1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "oidc: RAND_bytes() failed for HMAC secret");
            return NGX_ERROR;
        }
        mcf->secret_initialized = 1;
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

    /*
     * Register $oidc_claim_* as a prefix variable.  A single handler covers
     * all claim names: the three fixed claims (sub, email, name) restored from
     * the session cookie, plus any arbitrary claim extracted from the JWT on
     * the initial authentication request.
     *
     * Examples:
     *   proxy_set_header X-Remote-User   $oidc_claim_sub;
     *   proxy_set_header X-Remote-Groups $oidc_claim_groups;
     *   proxy_set_header X-Tenant-ID     $oidc_claim_tenant_id;
     */
    ngx_str_t claim_prefix = ngx_string("oidc_claim_");
    var = ngx_http_add_variable(cf, &claim_prefix,
                                NGX_HTTP_VAR_PREFIX | NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_claim_variable;
    var->data = 0;

    ngx_str_t at_name = ngx_string("oidc_access_token");
    var = ngx_http_add_variable(cf, &at_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_access_token_variable;
    var->data = 0;

    ngx_str_t disc_url_name = ngx_string("oidc_discovery_url");
    var = ngx_http_add_variable(cf, &disc_url_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_discovery_url_variable;
    var->data = 0;

    ngx_str_t jwks_url_name = ngx_string("oidc_jwks_url");
    var = ngx_http_add_variable(cf, &jwks_url_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_jwks_url_variable;
    var->data = 0;

    ngx_str_t userinfo_url_name = ngx_string("oidc_userinfo_url");
    var = ngx_http_add_variable(cf, &userinfo_url_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) return NGX_ERROR;
    var->get_handler = ngx_http_oidc_userinfo_url_variable;
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
    ngx_http_oidc_init_process,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};
