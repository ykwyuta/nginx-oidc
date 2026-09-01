/*
 * ngx_http_oidc_module — OpenID Connect Relying Party for NGINX Open Source.
 *
 * Implements the OAuth 2.0 Authorization Code Flow with PKCE (S256) and the
 * OpenID Connect ID Token validation rules of OIDC Core 3.1.3.7.
 *
 * All IdP communication is performed with non-blocking NGINX subrequests to
 * internal locations (/_oidc_discovery, /_oidc_token, /_oidc_jwks and
 * /_oidc_userinfo) so the event loop is never blocked.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>
#include <jwt.h>


#define OIDC_SESSION_MAX_PAYLOAD  3500
#define OIDC_DISCOVERY_TTL        3600
#define OIDC_CLOCK_SKEW           60
#define OIDC_RETURN_TO_MAX        2048
#define OIDC_COOKIE_ATTRS         "; HttpOnly; Secure; SameSite=Lax; Path=/"
#define OIDC_COOKIE_EXPIRED       "=; Expires=Thu, 01 Jan 1970 00:00:00 GMT;"    \
                                  " HttpOnly; Secure; SameSite=Lax; Path=/"

/* Maximum size of a single token kept in the shared session store. */
#define OIDC_MAX_TOKEN_LEN        16384

/* Which step of the flow a token subrequest belongs to. */
#define OIDC_PHASE_LOGIN          0
#define OIDC_PHASE_REFRESH        1
#define OIDC_PHASE_BACKCHANNEL    2

/* Where the session lives. */
#define OIDC_STORE_COOKIE         0
#define OIDC_STORE_SHM            1
#define OIDC_STORE_REDIS          2

/* Redis operations. */
#define OIDC_REDIS_NONE           0
#define OIDC_REDIS_LOAD           1
#define OIDC_REDIS_SAVE           2
#define OIDC_REDIS_DELETE         3
#define OIDC_REDIS_PURGE          4

/* What to do once a Redis operation completes. */
#define OIDC_AFTER_RESUME         0
#define OIDC_AFTER_LOGIN          1
#define OIDC_AFTER_LOGOUT         2
#define OIDC_AFTER_REFRESH        3

/* Configuration context of an "oidc_provider <name> { ... }" block. */
#define NGX_HTTP_OIDC_PROVIDER_CONF  0x02000000

/* Client authentication methods (oidc_client_auth). */
#define OIDC_CLIENT_AUTH_BASIC        0
#define OIDC_CLIENT_AUTH_POST         1
#define OIDC_CLIENT_AUTH_SECRET_JWT   2
#define OIDC_CLIENT_AUTH_PRIVATE_JWT  3

#define OIDC_ASSERTION_TYPE                                                   \
    "&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3A"                   \
    "client-assertion-type%3Ajwt-bearer&client_assertion="

/* Maximum age of a back-channel logout token. */
#define OIDC_LOGOUT_TOKEN_MAX_AGE 300

#define OIDC_SESSION_RECORD_VERSION "1"


/*
 * Provider metadata obtained from the discovery document.
 */
typedef struct {
    ngx_str_t issuer;
    ngx_str_t authorization_endpoint;
    ngx_str_t token_endpoint;
    ngx_str_t jwks_uri;
    ngx_str_t userinfo_endpoint;       /* optional */
    ngx_str_t end_session_endpoint;    /* optional, RP-Initiated Logout */
    ngx_str_t introspection_endpoint;  /* optional, RFC 7662 */
} ngx_http_oidc_provider_metadata_t;


/*
 * Fixed claims extracted from the ID token / UserInfo response.
 */
typedef struct {
    ngx_str_t sub;
    ngx_str_t email;
    ngx_str_t name;
} ngx_http_oidc_claims_t;


/*
 * Key/value entry backing the $oidc_claim_<name> prefix variable.
 */
typedef struct {
    ngx_str_t key;
    ngx_str_t value;
} ngx_http_oidc_claim_entry_t;


/*
 * Per-location runtime cache of the discovery document.
 *
 * The cache lives in its own pool so that a refresh can release the previous
 * generation.  Requests never point into this pool: ngx_http_oidc_access_handler
 * copies the metadata it needs into the request pool, so destroying the old
 * pool on refresh can never affect an in-flight request.
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t  *metadata;
    ngx_pool_t                         *pool;
    time_t                              expires;
} ngx_http_oidc_cache_t;


/*
 * Main configuration: only worker-wide state (the session cookie HMAC key).
 */
typedef struct {
    u_char           hmac_secret[32];
    ngx_uint_t       secret_initialized:1;
    ngx_str_t        cookie_secret;

    ngx_array_t     *providers;  /* named oidc_provider blocks */
    ngx_uint_t       store;      /* OIDC_STORE_* */
    ngx_shm_zone_t  *shm_zone;   /* oidc_session_store <size>: shared memory */
    ssize_t          shm_size;
} ngx_http_oidc_main_conf_t;


/*
 * Location configuration.
 */
typedef struct {
    ngx_flag_t   auth_oidc;
    ngx_str_t    oidc_provider;
    ngx_str_t    client_id;
    ngx_str_t    client_secret;
    ngx_str_t    redirect_uri;
    ngx_str_t    oidc_scope;
    ngx_flag_t   oidc_use_userinfo;
    time_t       session_timeout;
    ngx_array_t *session_claims;      /* ngx_str_t, NULL = every non-protocol claim */

    ngx_str_t    logout_uri;                /* oidc_logout_uri */
    ngx_str_t    backchannel_logout_uri;
    ngx_str_t    frontchannel_logout_uri;
    ngx_str_t    post_logout_redirect_uri;
    ngx_uint_t   client_auth;               /* OIDC_CLIENT_AUTH_* */
    ngx_str_t    client_jwt_key;            /* PEM for private_key_jwt */
    ngx_str_t    client_jwt_kid;
    ngx_str_t    client_jwt_alg;
    ngx_flag_t   refresh_token;             /* oidc_refresh_token */
    ngx_flag_t   introspection;             /* oidc_introspection */
    time_t       introspection_interval;
    ngx_http_complex_value_t *auth_args;    /* oidc_auth_request_args */

    ngx_str_t    provider_name;       /* auth_oidc <name> */

    ngx_http_upstream_conf_t redis_upstream;   /* oidc_redis_pass */
    ngx_str_t    redis_password;
    ngx_int_t    redis_database;

    ngx_str_t    client_basic;        /* "Basic base64(client_id:client_secret)" */
    ngx_str_t    client_post;         /* "&client_secret=..." for client_secret_post */
    ngx_str_t    callback_path;       /* path part of oidc_redirect_uri */
    ngx_str_t    logout_path;         /* path part of oidc_logout_uri */
    ngx_str_t    backchannel_path;
    ngx_str_t    frontchannel_path;
    ngx_http_oidc_cache_t *cache;     /* per-location discovery cache */
} ngx_http_oidc_loc_conf_t;


/*
 * A named provider defined by an "oidc_provider <name> { ... }" block.
 */
typedef struct {
    ngx_str_t                  name;
    ngx_http_oidc_loc_conf_t  *conf;
} ngx_http_oidc_provider_t;


/*
 * Per-request context.
 *
 * `waiting` marks that a subrequest chain is in flight.  NGINX re-runs the
 * parent's phases every time one of those subrequests is finalised, so the
 * access handler must return NGX_AGAIN until the chain reports a result via
 * `done` / `status`.  Without this the parent would race ahead of its own
 * subrequests and finalise the request before the ID token is verified.
 */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  /* request-local copy */

    ngx_uint_t discovery_attempted:1;
    ngx_uint_t token_attempted:1;
    ngx_uint_t userinfo_attempted:1;
    ngx_uint_t waiting:1;
    ngx_uint_t done:1;

    /*
     * NGINX may finalise the same subrequest more than once (for instance when
     * it is still linked in the parent's postponed chain), and every finalise
     * runs the post-subrequest handler again.  These bits make each completion
     * handler run exactly once.
     */
    ngx_uint_t discovery_handled:1;
    ngx_uint_t token_handled:1;
    ngx_uint_t jwks_handled:1;
    ngx_uint_t userinfo_handled:1;
    ngx_uint_t introspect_handled:1;

    ngx_uint_t refresh_attempted:1;
    ngx_uint_t refreshed:1;
    ngx_uint_t introspect_attempted:1;

    ngx_uint_t phase;                 /* OIDC_PHASE_LOGIN / OIDC_PHASE_REFRESH */

    ngx_int_t  status;                /* final status once `done` is set */

    ngx_str_t  id_token;
    ngx_str_t  access_token;
    ngx_str_t  refresh_token;
    time_t     access_expires;        /* 0 when the IdP sent no expires_in */
    time_t     introspected;          /* last successful introspection */
    ngx_str_t  sid;                   /* server side session id (store mode) */
    ngx_str_t  oidc_sid;              /* "sid" claim of the ID token, if any */
    time_t     session_issued;        /* when the running session was created */

    ngx_str_t  client_assertion;      /* JWT built for the *_jwt auth methods */
    ngx_str_t  redis_cmd;             /* RESP command to run */
    ngx_str_t  redis_value;           /* bulk reply of the last GET */
    ngx_str_t  pending_cookie;        /* cookie to set once the save succeeds */
    ngx_uint_t redis_op;
    ngx_uint_t redis_after;
    ngx_uint_t redis_handled:1;
    ngx_uint_t redis_found:1;
    ngx_uint_t body_read:1;
    ngx_uint_t jwks_started:1;
    ngx_uint_t purged:1;
    ngx_uint_t session_loaded:1;
    ngx_uint_t session_valid:1;
    ngx_http_oidc_claims_t claims;
    ngx_array_t *extra_claims;

    /* Values published to the internal locations through variables. */
    ngx_str_t  discovery_url;
    ngx_str_t  token_url;
    ngx_str_t  jwks_url;
    ngx_str_t  userinfo_url;
    ngx_str_t  introspect_url;
    ngx_str_t  token_body;
    ngx_str_t  token_basic;
    ngx_str_t  userinfo_bearer;
    ngx_str_t  introspect_body;
} ngx_http_oidc_ctx_t;


extern ngx_module_t ngx_http_oidc_module;

static ngx_int_t ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r,
    ngx_pool_t *pool, const u_char *data, size_t len,
    ngx_http_oidc_provider_metadata_t *metadata);
static ngx_int_t ngx_http_oidc_start_jwks_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_start_userinfo_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_oidc_token_handler(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static ngx_int_t ngx_http_oidc_jwks_handler(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static ngx_int_t ngx_http_oidc_userinfo_handler(ngx_http_request_t *r,
    void *data, ngx_int_t rc);
static void ngx_http_oidc_issue_session_and_redirect(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf);
static ngx_int_t ngx_http_oidc_save_session(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_loc_conf_t *lcf, time_t issued, ngx_uint_t after);
static time_t ngx_http_oidc_session_lifetime(ngx_http_oidc_loc_conf_t *lcf);
static ngx_int_t ngx_http_oidc_load_session(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_ctx_t *ctx);
static ngx_int_t ngx_http_oidc_add_cookie(ngx_http_request_t *r,
    const char *name, size_t name_len, ngx_str_t *value, time_t max_age);
static ngx_int_t ngx_http_oidc_validate_logout_token(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, json_t *payload);
static ngx_int_t ngx_http_oidc_purge_sessions(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf);
static void *ngx_http_oidc_create_loc_conf(ngx_conf_t *cf);


/* ------------------------------------------------------------------------ *
 *  Small helpers
 * ------------------------------------------------------------------------ */

/*
 * Mark the subrequest chain as finished and record the status the access
 * handler must return when NGINX resumes the parent request.
 */
static void
ngx_http_oidc_finish(ngx_http_request_t *r, ngx_int_t status)
{
    ngx_http_oidc_ctx_t *ctx;

    if (r == NULL) {
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx != NULL) {
        ctx->waiting = 0;
        ctx->done    = 1;
        ctx->status  = status;
    }

    r->write_event_handler = ngx_http_core_run_phases;
}


/*
 * Percent-encode `src` following RFC 3986 (unreserved characters are kept).
 * Used for query string and application/x-www-form-urlencoded values, where
 * ngx_escape_uri()'s tables are deliberately more permissive than we want.
 */
static size_t
ngx_http_oidc_escaped_len(ngx_str_t *src)
{
    size_t  i, len = 0;
    u_char  c;

    for (i = 0; i < src->len; i++) {
        c = src->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~')
        {
            len += 1;
        } else {
            len += 3;
        }
    }

    return len;
}


static u_char *
ngx_http_oidc_escape(u_char *dst, ngx_str_t *src)
{
    static const u_char hex[] = "0123456789ABCDEF";
    size_t  i;
    u_char  c;

    for (i = 0; i < src->len; i++) {
        c = src->data[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
            || (c >= '0' && c <= '9')
            || c == '-' || c == '.' || c == '_' || c == '~')
        {
            *dst++ = c;
        } else {
            *dst++ = '%';
            *dst++ = hex[c >> 4];
            *dst++ = hex[c & 0x0f];
        }
    }

    return dst;
}


/*
 * Cookie helper: search for a named cookie in the request headers.
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
 * Append a Set-Cookie header built from `name=value` plus the shared cookie
 * attributes.  `max_age` < 0 omits the Max-Age attribute.
 */
static ngx_int_t
ngx_http_oidc_add_cookie(ngx_http_request_t *r, const char *name,
    size_t name_len, ngx_str_t *value, time_t max_age)
{
    ngx_table_elt_t  *h;
    u_char           *p;
    size_t            len;
    u_char            age_buf[sizeof("; Max-Age=") - 1 + NGX_TIME_T_LEN];
    size_t            age_len = 0;

    if (max_age >= 0) {
        age_len = ngx_snprintf(age_buf, sizeof(age_buf), "; Max-Age=%T",
                               max_age) - age_buf;
    }

    len = name_len + 1 + value->len + age_len
        + sizeof(OIDC_COOKIE_ATTRS) - 1;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Set-Cookie");
    h->value.data = ngx_pnalloc(r->pool, len);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }

    p = h->value.data;
    p = ngx_cpymem(p, name, name_len);
    *p++ = '=';
    p = ngx_cpymem(p, value->data, value->len);
    if (age_len) {
        p = ngx_cpymem(p, age_buf, age_len);
    }
    p = ngx_cpymem(p, OIDC_COOKIE_ATTRS, sizeof(OIDC_COOKIE_ATTRS) - 1);

    h->value.len = p - h->value.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_clear_cookie(ngx_http_request_t *r, const char *name_eq_attrs)
{
    ngx_table_elt_t  *h;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Set-Cookie");
    h->value.len  = ngx_strlen(name_eq_attrs);
    h->value.data = (u_char *) name_eq_attrs;

    return NGX_OK;
}


/*
 * Copy an ngx_str_t into `pool`.
 */
static ngx_int_t
ngx_http_oidc_str_copy(ngx_pool_t *pool, ngx_str_t *dst, const char *src,
    size_t len)
{
    dst->data = ngx_pnalloc(pool, len + 1);
    if (dst->data == NULL) {
        dst->len = 0;
        return NGX_ERROR;
    }

    ngx_memcpy(dst->data, src, len);
    dst->data[len] = '\0';
    dst->len = len;

    return NGX_OK;
}


/*
 * Strip a trailing '/' so that "https://idp/" and "https://idp" behave alike.
 */
static void
ngx_http_oidc_trim_slash(ngx_str_t *s)
{
    while (s->len > 1 && s->data[s->len - 1] == '/') {
        s->len--;
    }
}


/* ------------------------------------------------------------------------ *
 *  JWK -> PEM (SubjectPublicKeyInfo)
 *
 *  libjwt 1.x has no JWKS support: jwt_decode() expects a PEM encoded public
 *  key.  Passing the raw JWKS document with key_len == 0 (as an earlier
 *  revision of this module did) makes libjwt skip signature verification
 *  entirely, so the key material has to be assembled here.  The DER is written
 *  by hand to avoid the OpenSSL 1.1 / 3.x low-level key API split.
 * ------------------------------------------------------------------------ */

static const u_char oidc_algid_rsa[] = {
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
};

static const u_char oidc_oid_ec_pubkey[] = {
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01
};

static const u_char oidc_oid_p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static const u_char oidc_oid_p384[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22
};

static const u_char oidc_oid_p521[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23
};


static size_t
oidc_der_len_bytes(size_t len)
{
    if (len < 0x80)   return 1;
    if (len <= 0xff)  return 2;
    if (len <= 0xffff) return 3;
    return 4;
}


static u_char *
oidc_der_put_len(u_char *p, size_t len)
{
    if (len < 0x80) {
        *p++ = (u_char) len;

    } else if (len <= 0xff) {
        *p++ = 0x81;
        *p++ = (u_char) len;

    } else if (len <= 0xffff) {
        *p++ = 0x82;
        *p++ = (u_char) (len >> 8);
        *p++ = (u_char) len;

    } else {
        *p++ = 0x83;
        *p++ = (u_char) (len >> 16);
        *p++ = (u_char) (len >> 8);
        *p++ = (u_char) len;
    }

    return p;
}


/*
 * Base64URL-decode a JSON string member into `pool`.
 */
static ngx_int_t
oidc_jwk_member_bin(ngx_pool_t *pool, json_t *obj, const char *name,
    ngx_str_t *out)
{
    json_t     *v;
    ngx_str_t   enc;

    v = json_object_get(obj, name);
    if (!json_is_string(v)) {
        return NGX_DECLINED;
    }

    enc.data = (u_char *) json_string_value(v);
    enc.len  = ngx_strlen(enc.data);
    if (enc.len == 0) {
        return NGX_DECLINED;
    }

    out->data = ngx_pnalloc(pool, ngx_base64_decoded_length(enc.len));
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(out, &enc) != NGX_OK) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * Wrap a DER SubjectPublicKeyInfo in PEM armour.
 */
static ngx_int_t
oidc_der_to_pem(ngx_pool_t *pool, ngx_str_t *der, ngx_str_t *pem)
{
    static const char  begin[] = "-----BEGIN PUBLIC KEY-----\n";
    static const char  end[]   = "-----END PUBLIC KEY-----\n";
    ngx_str_t          b64;
    u_char            *p;
    size_t             i, line;

    b64.data = ngx_pnalloc(pool, ngx_base64_encoded_length(der->len));
    if (b64.data == NULL) {
        return NGX_ERROR;
    }
    ngx_encode_base64(&b64, der);

    pem->data = ngx_pnalloc(pool, sizeof(begin) - 1 + b64.len
                                  + b64.len / 64 + 2 + sizeof(end));
    if (pem->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(pem->data, begin, sizeof(begin) - 1);

    for (i = 0; i < b64.len; i += 64) {
        line = ngx_min(64, b64.len - i);
        p = ngx_cpymem(p, b64.data + i, line);
        *p++ = '\n';
    }

    p = ngx_cpymem(p, end, sizeof(end) - 1);
    *p = '\0';

    pem->len = p - pem->data;

    return NGX_OK;
}


static ngx_int_t
oidc_jwk_rsa_to_pem(ngx_pool_t *pool, json_t *jwk, ngx_str_t *pem)
{
    ngx_str_t   n, e, der;
    size_t      n_skip, e_skip, n_len, e_len;
    size_t      inner, rsa_seq, bits_len, algid_len, total;
    ngx_uint_t  n_pad, e_pad;
    u_char     *p;

    if (oidc_jwk_member_bin(pool, jwk, "n", &n) != NGX_OK
        || oidc_jwk_member_bin(pool, jwk, "e", &e) != NGX_OK
        || n.len == 0 || e.len == 0)
    {
        return NGX_DECLINED;
    }

    /* DER INTEGERs are signed: drop leading zeros, re-add one if bit 7 is set */
    for (n_skip = 0; n_skip + 1 < n.len && n.data[n_skip] == 0; n_skip++) { /* void */ }
    for (e_skip = 0; e_skip + 1 < e.len && e.data[e_skip] == 0; e_skip++) { /* void */ }

    n_pad = (n.data[n_skip] & 0x80) ? 1 : 0;
    e_pad = (e.data[e_skip] & 0x80) ? 1 : 0;

    n_len = n.len - n_skip + n_pad;
    e_len = e.len - e_skip + e_pad;

    inner     = 1 + oidc_der_len_bytes(n_len) + n_len
              + 1 + oidc_der_len_bytes(e_len) + e_len;
    rsa_seq   = 1 + oidc_der_len_bytes(inner) + inner;
    bits_len  = 1 + rsa_seq;                       /* unused-bits octet */
    algid_len = sizeof(oidc_algid_rsa);
    total     = algid_len + 1 + oidc_der_len_bytes(bits_len) + bits_len;

    der.data = ngx_pnalloc(pool, 1 + oidc_der_len_bytes(total) + total);
    if (der.data == NULL) {
        return NGX_ERROR;
    }

    p = der.data;

    *p++ = 0x30;                                   /* SubjectPublicKeyInfo */
    p = oidc_der_put_len(p, total);
    p = ngx_cpymem(p, oidc_algid_rsa, algid_len);  /* AlgorithmIdentifier */

    *p++ = 0x03;                                   /* BIT STRING */
    p = oidc_der_put_len(p, bits_len);
    *p++ = 0x00;

    *p++ = 0x30;                                   /* RSAPublicKey */
    p = oidc_der_put_len(p, inner);

    *p++ = 0x02;                                   /* INTEGER n */
    p = oidc_der_put_len(p, n_len);
    if (n_pad) {
        *p++ = 0x00;
    }
    p = ngx_cpymem(p, n.data + n_skip, n.len - n_skip);

    *p++ = 0x02;                                   /* INTEGER e */
    p = oidc_der_put_len(p, e_len);
    if (e_pad) {
        *p++ = 0x00;
    }
    p = ngx_cpymem(p, e.data + e_skip, e.len - e_skip);

    der.len = p - der.data;

    return oidc_der_to_pem(pool, &der, pem);
}


static ngx_int_t
oidc_jwk_ec_to_pem(ngx_pool_t *pool, json_t *jwk, ngx_str_t *pem)
{
    ngx_str_t      x, y, der;
    json_t        *crv;
    const char    *crv_name;
    const u_char  *oid;
    size_t         oid_len, coord, point_len, bits_len, algid_len, total;
    u_char        *p;

    crv = json_object_get(jwk, "crv");
    if (!json_is_string(crv)) {
        return NGX_DECLINED;
    }
    crv_name = json_string_value(crv);

    if (ngx_strcmp(crv_name, "P-256") == 0) {
        oid = oidc_oid_p256; oid_len = sizeof(oidc_oid_p256); coord = 32;

    } else if (ngx_strcmp(crv_name, "P-384") == 0) {
        oid = oidc_oid_p384; oid_len = sizeof(oidc_oid_p384); coord = 48;

    } else if (ngx_strcmp(crv_name, "P-521") == 0) {
        oid = oidc_oid_p521; oid_len = sizeof(oidc_oid_p521); coord = 66;

    } else {
        return NGX_DECLINED;
    }

    if (oidc_jwk_member_bin(pool, jwk, "x", &x) != NGX_OK
        || oidc_jwk_member_bin(pool, jwk, "y", &y) != NGX_OK
        || x.len > coord || y.len > coord)
    {
        return NGX_DECLINED;
    }

    point_len = 1 + 2 * coord;              /* 0x04 || X || Y */
    bits_len  = 1 + point_len;              /* unused-bits octet */
    algid_len = 1 + oidc_der_len_bytes(sizeof(oidc_oid_ec_pubkey) + oid_len)
              + sizeof(oidc_oid_ec_pubkey) + oid_len;
    total     = algid_len + 1 + oidc_der_len_bytes(bits_len) + bits_len;

    der.data = ngx_pnalloc(pool, 1 + oidc_der_len_bytes(total) + total);
    if (der.data == NULL) {
        return NGX_ERROR;
    }

    p = der.data;
    *p++ = 0x30;
    p = oidc_der_put_len(p, total);

    *p++ = 0x30;
    p = oidc_der_put_len(p, sizeof(oidc_oid_ec_pubkey) + oid_len);
    p = ngx_cpymem(p, oidc_oid_ec_pubkey, sizeof(oidc_oid_ec_pubkey));
    p = ngx_cpymem(p, oid, oid_len);

    *p++ = 0x03;
    p = oidc_der_put_len(p, bits_len);
    *p++ = 0x00;
    *p++ = 0x04;

    ngx_memzero(p, coord - x.len);
    p += coord - x.len;
    p = ngx_cpymem(p, x.data, x.len);

    ngx_memzero(p, coord - y.len);
    p += coord - y.len;
    p = ngx_cpymem(p, y.data, y.len);

    der.len = p - der.data;

    return oidc_der_to_pem(pool, &der, pem);
}


/*
 * Decode the JOSE header of `token` and return its "alg" and "kid".
 */
static ngx_int_t
ngx_http_oidc_jwt_header(ngx_http_request_t *r, ngx_str_t *token,
    ngx_str_t *alg, ngx_str_t *kid)
{
    u_char     *dot;
    ngx_str_t   enc, raw;
    json_t     *root, *v;
    json_error_t jerr;

    dot = ngx_strlchr(token->data, token->data + token->len, '.');
    if (dot == NULL || dot == token->data) {
        return NGX_ERROR;
    }

    enc.data = token->data;
    enc.len  = dot - token->data;

    raw.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(enc.len) + 1);
    if (raw.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&raw, &enc) != NGX_OK) {
        return NGX_ERROR;
    }
    raw.data[raw.len] = '\0';

    root = json_loadb((const char *) raw.data, raw.len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        if (root) {
            json_decref(root);
        }
        return NGX_ERROR;
    }

    ngx_str_null(alg);
    ngx_str_null(kid);

    v = json_object_get(root, "alg");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(r->pool, alg, json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    v = json_object_get(root, "kid");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(r->pool, kid, json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    json_decref(root);

    return alg->len ? NGX_OK : NGX_ERROR;
}


/*
 * Only asymmetric signature algorithms are accepted.  "none" and the HS*
 * family are rejected outright: with a public key as the shared secret an
 * HS256 token would otherwise be trivially forgeable (algorithm confusion).
 */
static ngx_int_t
ngx_http_oidc_alg_allowed(ngx_str_t *alg, const char **kty)
{
    static const char *rsa_algs[] = { "RS256", "RS384", "RS512",
                                      "PS256", "PS384", "PS512", NULL };
    static const char *ec_algs[]  = { "ES256", "ES384", "ES512", NULL };
    ngx_uint_t  i;

    for (i = 0; rsa_algs[i]; i++) {
        if (alg->len == 5
            && ngx_strncmp(alg->data, rsa_algs[i], 5) == 0)
        {
            *kty = "RSA";
            return NGX_OK;
        }
    }

    for (i = 0; ec_algs[i]; i++) {
        if (alg->len == 5
            && ngx_strncmp(alg->data, ec_algs[i], 5) == 0)
        {
            *kty = "EC";
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


/* ------------------------------------------------------------------------ *
 *  Claim handling
 * ------------------------------------------------------------------------ */

/*
 * Render a JSON claim value as a string.
 *
 * Strings, numbers and booleans map directly; arrays are flattened into a
 * comma separated list (this is what IdPs such as Keycloak or Azure AD return
 * for "groups" and "roles").  Objects and nulls are skipped.
 */
static ngx_int_t
ngx_http_oidc_claim_to_str(ngx_pool_t *pool, json_t *val, ngx_str_t *out)
{
    char        buf[64];
    size_t      i, n, len;
    json_t     *item;
    u_char     *p;
    ngx_array_t parts;

    if (json_is_string(val)) {
        return ngx_http_oidc_str_copy(pool, out, json_string_value(val),
                                      ngx_strlen(json_string_value(val)));
    }

    if (json_is_integer(val)) {
        len = ngx_snprintf((u_char *) buf, sizeof(buf), "%L",
                           (int64_t) json_integer_value(val)) - (u_char *) buf;
        return ngx_http_oidc_str_copy(pool, out, buf, len);
    }

    if (json_is_real(val)) {
        len = (size_t) snprintf(buf, sizeof(buf), "%g", json_real_value(val));
        if (len >= sizeof(buf)) {
            return NGX_DECLINED;
        }
        return ngx_http_oidc_str_copy(pool, out, buf, len);
    }

    if (json_is_boolean(val)) {
        return json_is_true(val)
               ? ngx_http_oidc_str_copy(pool, out, "true", 4)
               : ngx_http_oidc_str_copy(pool, out, "false", 5);
    }

    if (json_is_array(val)) {
        n = json_array_size(val);
        if (n == 0) {
            return NGX_DECLINED;
        }

        if (ngx_array_init(&parts, pool, n, sizeof(ngx_str_t)) != NGX_OK) {
            return NGX_ERROR;
        }

        len = 0;
        for (i = 0; i < n; i++) {
            ngx_str_t *s = ngx_array_push(&parts);
            if (s == NULL) {
                return NGX_ERROR;
            }
            ngx_str_null(s);

            item = json_array_get(val, i);
            if (json_is_array(item) || json_is_object(item)) {
                continue;
            }
            if (ngx_http_oidc_claim_to_str(pool, item, s) != NGX_OK) {
                ngx_str_null(s);
                continue;
            }
            len += s->len + 1;
        }

        if (len == 0) {
            return NGX_DECLINED;
        }

        out->data = ngx_pnalloc(pool, len);
        if (out->data == NULL) {
            return NGX_ERROR;
        }

        p = out->data;
        for (i = 0; i < parts.nelts; i++) {
            ngx_str_t *s = &((ngx_str_t *) parts.elts)[i];
            if (s->len == 0) {
                continue;
            }
            if (p != out->data) {
                *p++ = ',';
            }
            p = ngx_cpymem(p, s->data, s->len);
        }

        out->len = p - out->data;

        return NGX_OK;
    }

    return NGX_DECLINED;
}


/*
 * Protocol claims are never exported as $oidc_claim_* variables and never
 * stored in the session cookie: they carry no application meaning and would
 * only consume the (limited) cookie budget.  sub/email/name are excluded as
 * well because they have dedicated slots in the session payload.
 */
static ngx_int_t
ngx_http_oidc_claim_is_protocol(const char *name)
{
    static const char *skip[] = {
        "iss", "aud", "exp", "iat", "nbf", "jti", "nonce", "azp",
        "at_hash", "c_hash", "s_hash", "auth_time", "sid", "typ",
        "session_state", "sub", "email", "name", NULL
    };
    ngx_uint_t  i;

    for (i = 0; skip[i]; i++) {
        if (ngx_strcmp(name, skip[i]) == 0) {
            return 1;
        }
    }

    return 0;
}


/*
 * Decide whether a claim should be captured, honouring the oidc_claims
 * allow-list when one is configured.
 */
static ngx_int_t
ngx_http_oidc_claim_wanted(ngx_http_oidc_loc_conf_t *lcf, const char *name)
{
    ngx_str_t   *list;
    ngx_uint_t   i;
    size_t       len;

    if (lcf->session_claims != NULL) {
        list = lcf->session_claims->elts;
        len  = ngx_strlen(name);

        for (i = 0; i < lcf->session_claims->nelts; i++) {
            if (list[i].len == len
                && ngx_strncmp(list[i].data, name, len) == 0)
            {
                return 1;
            }
        }

        return 0;
    }

    return !ngx_http_oidc_claim_is_protocol(name);
}


/*
 * Insert or replace an entry in ctx->extra_claims.
 */
static ngx_int_t
ngx_http_oidc_set_claim(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    const char *key, ngx_str_t *value)
{
    ngx_http_oidc_claim_entry_t  *entries, *entry;
    ngx_uint_t                    i;
    size_t                        klen = ngx_strlen(key);

    if (ctx->extra_claims == NULL) {
        ctx->extra_claims = ngx_array_create(r->pool, 8,
                                             sizeof(ngx_http_oidc_claim_entry_t));
        if (ctx->extra_claims == NULL) {
            return NGX_ERROR;
        }
    }

    entries = ctx->extra_claims->elts;
    for (i = 0; i < ctx->extra_claims->nelts; i++) {
        if (entries[i].key.len == klen
            && ngx_strncmp(entries[i].key.data, key, klen) == 0)
        {
            entries[i].value = *value;
            return NGX_OK;
        }
    }

    entry = ngx_array_push(ctx->extra_claims);
    if (entry == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_str_copy(r->pool, &entry->key, key, klen) != NGX_OK) {
        ctx->extra_claims->nelts--;
        return NGX_ERROR;
    }

    entry->value = *value;

    return NGX_OK;
}


/*
 * Merge every wanted claim of a JSON object (ID token payload or UserInfo
 * response) into the request context.
 */
static void
ngx_http_oidc_merge_claims(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_loc_conf_t *lcf, json_t *obj)
{
    const char  *key;
    json_t      *val;
    ngx_str_t    str;

    json_object_foreach(obj, key, val) {

        if (json_is_string(val)) {
            if (ngx_strcmp(key, "sub") == 0) {
                (void) ngx_http_oidc_str_copy(r->pool, &ctx->claims.sub,
                            json_string_value(val),
                            ngx_strlen(json_string_value(val)));
                continue;
            }
            if (ngx_strcmp(key, "email") == 0) {
                (void) ngx_http_oidc_str_copy(r->pool, &ctx->claims.email,
                            json_string_value(val),
                            ngx_strlen(json_string_value(val)));
                continue;
            }
            if (ngx_strcmp(key, "name") == 0) {
                (void) ngx_http_oidc_str_copy(r->pool, &ctx->claims.name,
                            json_string_value(val),
                            ngx_strlen(json_string_value(val)));
                continue;
            }
            if (ngx_strcmp(key, "sid") == 0) {
                /* kept for back-channel and front-channel logout */
                (void) ngx_http_oidc_str_copy(r->pool, &ctx->oidc_sid,
                            json_string_value(val),
                            ngx_strlen(json_string_value(val)));
                continue;
            }
        }

        if (!ngx_http_oidc_claim_wanted(lcf, key)) {
            continue;
        }

        if (ngx_http_oidc_claim_to_str(r->pool, val, &str) != NGX_OK) {
            continue;
        }

        (void) ngx_http_oidc_set_claim(r, ctx, key, &str);
    }
}


/* ------------------------------------------------------------------------ *
 *  Session payload (shared by the cookie and the shared memory store)
 * ------------------------------------------------------------------------ */

/*
 * Serialise the claims:
 *
 *   B64(sub):B64(email):B64(name):issued_at[|B64(key):B64(value)]...
 *
 * Every field is Base64 encoded so that ':' inside a value cannot confuse the
 * parser.  The result is capped at OIDC_SESSION_MAX_PAYLOAD bytes so that a
 * cookie built from it stays within the browser's 4096 byte limit.
 */
static ngx_int_t
ngx_http_oidc_build_claims(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    time_t issued, ngx_str_t *out)
{
    ngx_http_oidc_claim_entry_t  *entries;
    ngx_str_t                     sub_b64, email_b64, name_b64;
    u_char                       *p, *buf;
    size_t                        len, i;

    sub_b64.len   = ngx_base64_encoded_length(ctx->claims.sub.len);
    email_b64.len = ngx_base64_encoded_length(ctx->claims.email.len);
    name_b64.len  = ngx_base64_encoded_length(ctx->claims.name.len);

    sub_b64.data   = ngx_pnalloc(r->pool, sub_b64.len);
    email_b64.data = ngx_pnalloc(r->pool, email_b64.len);
    name_b64.data  = ngx_pnalloc(r->pool, name_b64.len);

    if (sub_b64.data == NULL || email_b64.data == NULL
        || name_b64.data == NULL)
    {
        return NGX_ERROR;
    }

    ngx_encode_base64(&sub_b64,   &ctx->claims.sub);
    ngx_encode_base64(&email_b64, &ctx->claims.email);
    ngx_encode_base64(&name_b64,  &ctx->claims.name);

    len = sub_b64.len + email_b64.len + name_b64.len + 3 + NGX_TIME_T_LEN;

    if (ctx->extra_claims != NULL) {
        entries = ctx->extra_claims->elts;
        for (i = 0; i < ctx->extra_claims->nelts; i++) {
            len += 2 + ngx_base64_encoded_length(entries[i].key.len)
                     + ngx_base64_encoded_length(entries[i].value.len);
        }
    }

    buf = ngx_pnalloc(r->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = ngx_snprintf(buf, len, "%V:%V:%V:%T", &sub_b64, &email_b64, &name_b64,
                     issued);

    if (ctx->extra_claims != NULL) {
        entries = ctx->extra_claims->elts;

        for (i = 0; i < ctx->extra_claims->nelts; i++) {
            ngx_str_t kb64, vb64;
            size_t    need;

            kb64.len = ngx_base64_encoded_length(entries[i].key.len);
            vb64.len = ngx_base64_encoded_length(entries[i].value.len);
            need     = 2 + kb64.len + vb64.len;

            if ((size_t) (p - buf) + need > OIDC_SESSION_MAX_PAYLOAD) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "OIDC: session payload budget exhausted, "
                              "claim \"%V\" was dropped", &entries[i].key);
                continue;
            }

            kb64.data = ngx_pnalloc(r->pool, kb64.len);
            vb64.data = ngx_pnalloc(r->pool, vb64.len);
            if (kb64.data == NULL || vb64.data == NULL) {
                break;
            }

            ngx_encode_base64(&kb64, &entries[i].key);
            ngx_encode_base64(&vb64, &entries[i].value);

            *p++ = '|';
            p = ngx_cpymem(p, kb64.data, kb64.len);
            *p++ = ':';
            p = ngx_cpymem(p, vb64.data, vb64.len);
        }
    }

    out->data = buf;
    out->len  = p - buf;

    return NGX_OK;
}


/*
 * Restore the claims serialised by ngx_http_oidc_build_claims().
 */
static ngx_int_t
ngx_http_oidc_parse_claims(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *payload, time_t *issued)
{
    ngx_str_t   enc, dec;
    ngx_str_t  *field[3];
    u_char     *pl, *end, *c1, *c2, *c3, *ts_end, *pipe, *ep;
    ngx_uint_t  i;

    pl  = payload->data;
    end = payload->data + payload->len;

    c1 = ngx_strlchr(pl, end, ':');
    if (c1 == NULL) {
        return NGX_DECLINED;
    }
    c2 = ngx_strlchr(c1 + 1, end, ':');
    if (c2 == NULL) {
        return NGX_DECLINED;
    }
    c3 = ngx_strlchr(c2 + 1, end, ':');
    if (c3 == NULL) {
        return NGX_DECLINED;
    }

    pipe   = ngx_strlchr(c3 + 1, end, '|');
    ts_end = pipe ? pipe : end;

    *issued = ngx_atotm(c3 + 1, ts_end - (c3 + 1));
    if (*issued == NGX_ERROR) {
        return NGX_DECLINED;
    }

    field[0] = &ctx->claims.sub;
    field[1] = &ctx->claims.email;
    field[2] = &ctx->claims.name;

    enc.data = pl;
    enc.len  = c1 - pl;

    for (i = 0; i < 3; i++) {
        if (i == 1) {
            enc.data = c1 + 1;
            enc.len  = c2 - (c1 + 1);
        } else if (i == 2) {
            enc.data = c2 + 1;
            enc.len  = c3 - (c2 + 1);
        }

        dec.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(enc.len));
        if (dec.data == NULL) {
            return NGX_ERROR;
        }

        if (ngx_decode_base64(&dec, &enc) == NGX_OK) {
            *field[i] = dec;
        }
    }

    if (pipe == NULL) {
        return NGX_OK;
    }

    ep = pipe + 1;

    while (ep < end) {
        u_char    *next  = ngx_strlchr(ep, end, '|');
        u_char    *stop  = next ? next : end;
        u_char    *colon = ngx_strlchr(ep, stop, ':');
        ngx_str_t  kenc, venc, kdec, vdec;

        if (colon != NULL) {
            kenc.data = ep;
            kenc.len  = colon - ep;
            venc.data = colon + 1;
            venc.len  = stop - (colon + 1);

            kdec.data = ngx_pnalloc(r->pool,
                                    ngx_base64_decoded_length(kenc.len) + 1);
            vdec.data = ngx_pnalloc(r->pool,
                                    ngx_base64_decoded_length(venc.len) + 1);

            if (kdec.data != NULL && vdec.data != NULL
                && ngx_decode_base64(&kdec, &kenc) == NGX_OK
                && ngx_decode_base64(&vdec, &venc) == NGX_OK)
            {
                kdec.data[kdec.len] = '\0';

                if (ctx->extra_claims == NULL) {
                    ctx->extra_claims = ngx_array_create(r->pool, 8,
                                   sizeof(ngx_http_oidc_claim_entry_t));
                }

                if (ctx->extra_claims != NULL) {
                    ngx_http_oidc_claim_entry_t *entry =
                        ngx_array_push(ctx->extra_claims);
                    if (entry != NULL) {
                        entry->key   = kdec;
                        entry->value = vdec;
                    }
                }
            }
        }

        if (next == NULL) {
            break;
        }
        ep = next + 1;
    }

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  Redis client
 *
 *  A minimal RESP client built on the NGINX upstream framework, in the same
 *  spirit as ngx_http_memcached_module.  Only the replies this module needs
 *  are understood: simple strings, integers, bulk strings, nil and errors.
 *  Everything the module asks Redis to do fits in a single command, so a
 *  reply is never an array.
 * ------------------------------------------------------------------------ */

/* Per-subrequest state of a Redis call. */
typedef struct {
    ngx_uint_t  skip;        /* AUTH/SELECT replies still to consume */
    ngx_str_t   value;       /* bulk reply, copied out of the read buffer */
    ngx_uint_t  found:1;
} ngx_http_oidc_redis_ctx_t;


/*
 * Lua run server side so that a logout only costs one round trip: delete
 * every session listed in the index set, then the set itself.
 */
static ngx_str_t  ngx_http_oidc_purge_script = ngx_string(
    "local m=redis.call('SMEMBERS',KEYS[1]) "
    "for i=1,#m do redis.call('DEL','oidc:s:'..m[i]) end "
    "redis.call('DEL',KEYS[1]) return #m");

/*
 * Store the session and, when the ID token carried them, index it by "sid"
 * and by "sub" so that back-channel and front-channel logout can find it.
 */
static ngx_str_t  ngx_http_oidc_save_script = ngx_string(
    "redis.call('SETEX',KEYS[1],ARGV[1],ARGV[2]) "
    "if ARGV[4]~='' then redis.call('SADD',KEYS[2],ARGV[3]) "
    "redis.call('EXPIRE',KEYS[2],ARGV[1]) end "
    "if ARGV[5]~='' then redis.call('SADD',KEYS[3],ARGV[3]) "
    "redis.call('EXPIRE',KEYS[3],ARGV[1]) end return 1");


static size_t
ngx_http_oidc_resp_len(size_t len)
{
    return 1 + NGX_SIZE_T_LEN + 2 + len + 2;   /* $<len>\r\n<data>\r\n */
}


static u_char *
ngx_http_oidc_resp_bulk(u_char *p, ngx_str_t *s)
{
    p = ngx_sprintf(p, "$%uz" CRLF, s->len);
    p = ngx_cpymem(p, s->data, s->len);
    *p++ = CR;
    *p++ = LF;

    return p;
}


static u_char *
ngx_http_oidc_resp_cstr(u_char *p, const char *str)
{
    ngx_str_t  s;

    s.data = (u_char *) str;
    s.len  = ngx_strlen(str);

    return ngx_http_oidc_resp_bulk(p, &s);
}


static ngx_int_t
ngx_http_oidc_redis_create_request(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t   *lcf;
    ngx_http_oidc_redis_ctx_t  *rctx;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_chain_t                *cl;
    ngx_buf_t                  *b;
    u_char                     *p;
    size_t                      len;
    ngx_str_t                   db;
    u_char                      db_buf[NGX_INT_T_LEN];

    lcf  = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    rctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ctx  = ngx_http_get_module_ctx(r->main, ngx_http_oidc_module);

    if (rctx == NULL || ctx == NULL || ctx->redis_cmd.len == 0) {
        return NGX_ERROR;
    }

    db.data = db_buf;
    db.len  = ngx_sprintf(db_buf, "%i", lcf->redis_database) - db_buf;

    len = ctx->redis_cmd.len;

    if (lcf->redis_password.len) {
        len += sizeof("*2" CRLF) - 1
             + ngx_http_oidc_resp_len(sizeof("AUTH") - 1)
             + ngx_http_oidc_resp_len(lcf->redis_password.len);
    }

    if (lcf->redis_database > 0) {
        len += sizeof("*2" CRLF) - 1
             + ngx_http_oidc_resp_len(sizeof("SELECT") - 1)
             + ngx_http_oidc_resp_len(db.len);
    }

    b = ngx_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf  = b;
    cl->next = NULL;
    r->upstream->request_bufs = cl;

    p = b->last;

    if (lcf->redis_password.len) {
        p = ngx_cpymem(p, "*2" CRLF, sizeof("*2" CRLF) - 1);
        p = ngx_http_oidc_resp_cstr(p, "AUTH");
        p = ngx_http_oidc_resp_bulk(p, &lcf->redis_password);
        rctx->skip++;
    }

    if (lcf->redis_database > 0) {
        p = ngx_cpymem(p, "*2" CRLF, sizeof("*2" CRLF) - 1);
        p = ngx_http_oidc_resp_cstr(p, "SELECT");
        p = ngx_http_oidc_resp_bulk(p, &db);
        rctx->skip++;
    }

    p = ngx_cpymem(p, ctx->redis_cmd.data, ctx->redis_cmd.len);

    b->last = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_redis_reinit_request(ngx_http_request_t *r)
{
    ngx_http_oidc_redis_ctx_t  *rctx;

    rctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (rctx != NULL) {
        rctx->skip  = 0;
        rctx->found = 0;
        ngx_str_null(&rctx->value);
    }

    return NGX_OK;
}


/*
 * Wait until the whole reply is in the read buffer and then hand it over.
 *
 * Returning NGX_AGAIN until the payload is complete keeps the body out of the
 * upstream body machinery entirely: by the time NGX_OK is returned there is
 * nothing left to read, and the value has been copied out of the buffer,
 * which NGINX is free to reset afterwards.
 */
static ngx_int_t
ngx_http_oidc_redis_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t        *u = r->upstream;
    ngx_http_oidc_redis_ctx_t  *rctx;
    u_char                     *p, *last, *crlf, *start;
    ngx_int_t                   len;

    rctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (rctx == NULL) {
        return NGX_ERROR;
    }

    for ( ;; ) {

        p    = u->buffer.pos;
        last = u->buffer.last;

        crlf = ngx_strlchr(p, last, LF);
        if (crlf == NULL || crlf == p || crlf[-1] != CR) {
            return NGX_AGAIN;
        }
        crlf--;                                    /* points at CR */

        if (rctx->skip == 0) {
            start = p;
            break;
        }

        if (*p == '-') {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: redis refused AUTH/SELECT: \"%*s\"",
                          (size_t) (crlf - p), p);
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        rctx->skip--;
        u->buffer.pos = crlf + 2;
    }

    switch (*p) {

    case '+':                                      /* simple string */
    case ':':                                      /* integer */
        u->headers_in.status_n = NGX_HTTP_OK;
        rctx->found = 1;
        break;

    case '$':                                      /* bulk string or nil */

        if (crlf - p == 3 && p[1] == '-' && p[2] == '1') {
            u->headers_in.status_n = NGX_HTTP_NOT_FOUND;
            break;
        }

        len = ngx_atoi(p + 1, crlf - (p + 1));
        if (len == NGX_ERROR || len < 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: malformed redis bulk reply");
            return NGX_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (last - (crlf + 2) < len + 2) {
            return NGX_AGAIN;                      /* payload not complete */
        }

        rctx->value.data = ngx_pnalloc(r->pool, len);
        if (rctx->value.data == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(rctx->value.data, crlf + 2, len);
        rctx->value.len = len;
        rctx->found     = 1;

        crlf += 2 + len;                           /* skip payload, land on CR */

        u->headers_in.status_n = NGX_HTTP_OK;
        break;

    case '-':                                      /* error */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: redis returned an error: \"%*s\"",
                      (size_t) (crlf - p), p);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;

    default:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: unexpected redis reply type '%c'", *p);
        return NGX_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /*
     * The reply has been copied already, but it is still handed to NGINX as
     * the response body: an upstream response of length zero would leave the
     * non-buffered machinery waiting for data that never comes, and the
     * subrequest would only end on the read timeout.
     */
    u->headers_in.content_length_n = (crlf + 2) - start;
    u->length                      = (ssize_t) u->headers_in.content_length_n;
    u->state->status               = u->headers_in.status_n;

    return NGX_OK;
}


/*
 * ngx_http_upstream_process_headers() resets u->length to -1, so the length of
 * the reply has to be published from here rather than from process_header().
 */
static ngx_int_t
ngx_http_oidc_redis_filter_init(void *data)
{
    ngx_http_request_t   *r = data;
    ngx_http_upstream_t  *u = r->upstream;

    u->length = (ssize_t) u->headers_in.content_length_n;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_redis_filter(void *data, ssize_t bytes)
{
    ngx_http_request_t   *r = data;
    ngx_http_upstream_t  *u = r->upstream;

    u->buffer.last += bytes;

    if (u->length > 0) {
        u->length -= bytes;
        if (u->length < 0) {
            u->length = 0;
        }
    }

    return NGX_OK;
}


static void
ngx_http_oidc_redis_abort_request(ngx_http_request_t *r)
{
}


static void
ngx_http_oidc_redis_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
}


/*
 * Content handler of the internal /_oidc_redis location.
 */
static ngx_int_t
ngx_http_oidc_redis_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t   *lcf;
    ngx_http_oidc_redis_ctx_t  *rctx;
    ngx_http_upstream_t        *u;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_redis_ctx_t));
    if (rctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * This is the subrequest's own context; the flow state lives on r->main
     * and is never looked up through this request.
     */
    ngx_http_set_ctx(r, rctx, ngx_http_oidc_module);

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    u = r->upstream;

    ngx_str_set(&u->schema, "redis://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_oidc_module;
    u->conf       = &lcf->redis_upstream;

    u->input_filter_init = ngx_http_oidc_redis_filter_init;
    u->input_filter      = ngx_http_oidc_redis_filter;
    u->input_filter_ctx  = r;

    u->create_request   = ngx_http_oidc_redis_create_request;
    u->reinit_request   = ngx_http_oidc_redis_reinit_request;
    u->process_header   = ngx_http_oidc_redis_process_header;
    u->abort_request    = ngx_http_oidc_redis_abort_request;
    u->finalize_request = ngx_http_oidc_redis_finalize_request;

    r->main->count++;

    ngx_http_upstream_init(r);

    return NGX_DONE;
}


/* ------------------------------------------------------------------------ *
 *  Session record (used by the Redis store)
 *
 *   1|issued|access_expires|introspected|B64(id)|B64(at)|B64(rt)|B64(sid)|claims
 *
 *  The claims block is last because it contains '|' itself.
 * ------------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_b64_field(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    dst->len  = ngx_base64_encoded_length(src->len);
    dst->data = ngx_pnalloc(pool, dst->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(dst, src);

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_build_record(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *claims, time_t issued, ngx_str_t *out)
{
    ngx_str_t  id64, at64, rt64, sid64;
    u_char    *p;
    size_t     len;

    if (ngx_http_oidc_b64_field(r->pool, &ctx->id_token, &id64) != NGX_OK
        || ngx_http_oidc_b64_field(r->pool, &ctx->access_token, &at64) != NGX_OK
        || ngx_http_oidc_b64_field(r->pool, &ctx->refresh_token, &rt64) != NGX_OK
        || ngx_http_oidc_b64_field(r->pool, &ctx->oidc_sid, &sid64) != NGX_OK)
    {
        return NGX_ERROR;
    }

    len = sizeof(OIDC_SESSION_RECORD_VERSION) - 1 + 8
        + 3 * NGX_TIME_T_LEN
        + id64.len + at64.len + rt64.len + sid64.len + claims->len;

    out->data = ngx_pnalloc(r->pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_snprintf(out->data, len,
                     OIDC_SESSION_RECORD_VERSION "|%T|%T|%T|%V|%V|%V|%V|%V",
                     issued, ctx->access_expires, ctx->introspected,
                     &id64, &at64, &rt64, &sid64, claims);

    out->len = p - out->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_record_field(u_char **p, u_char *end, ngx_str_t *field)
{
    u_char  *bar;

    bar = ngx_strlchr(*p, end, '|');
    if (bar == NULL) {
        return NGX_ERROR;
    }

    field->data = *p;
    field->len  = bar - *p;
    *p = bar + 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_record_b64(ngx_http_request_t *r, u_char **p, u_char *end,
    ngx_str_t *dst)
{
    ngx_str_t  enc;

    if (ngx_http_oidc_record_field(p, end, &enc) != NGX_OK) {
        return NGX_ERROR;
    }

    if (enc.len == 0) {
        ngx_str_null(dst);
        return NGX_OK;
    }

    dst->data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(enc.len) + 1);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64(dst, &enc) != NGX_OK) {
        return NGX_ERROR;
    }

    dst->data[dst->len] = '\0';

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_parse_record(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *rec, ngx_str_t *claims, time_t *issued)
{
    u_char     *p, *end;
    ngx_str_t   field;

    p   = rec->data;
    end = rec->data + rec->len;

    if (ngx_http_oidc_record_field(&p, end, &field) != NGX_OK
        || field.len != sizeof(OIDC_SESSION_RECORD_VERSION) - 1
        || ngx_strncmp(field.data, OIDC_SESSION_RECORD_VERSION,
                       field.len) != 0)
    {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_record_field(&p, end, &field) != NGX_OK) {
        return NGX_ERROR;
    }
    *issued = ngx_atotm(field.data, field.len);

    if (ngx_http_oidc_record_field(&p, end, &field) != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->access_expires = ngx_atotm(field.data, field.len);

    if (ngx_http_oidc_record_field(&p, end, &field) != NGX_OK) {
        return NGX_ERROR;
    }
    ctx->introspected = ngx_atotm(field.data, field.len);

    if (*issued == NGX_ERROR || ctx->access_expires == NGX_ERROR
        || ctx->introspected == NGX_ERROR)
    {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_record_b64(r, &p, end, &ctx->id_token) != NGX_OK
        || ngx_http_oidc_record_b64(r, &p, end, &ctx->access_token) != NGX_OK
        || ngx_http_oidc_record_b64(r, &p, end, &ctx->refresh_token) != NGX_OK
        || ngx_http_oidc_record_b64(r, &p, end, &ctx->oidc_sid) != NGX_OK)
    {
        return NGX_ERROR;
    }

    claims->data = p;
    claims->len  = end - p;

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  Redis session operations
 * ------------------------------------------------------------------------ */

static ngx_int_t ngx_http_oidc_redis_done(ngx_http_request_t *r, void *data,
    ngx_int_t rc);


/*
 * Serialise a RESP command and start the /_oidc_redis subrequest.
 */
static ngx_int_t
ngx_http_oidc_redis_call(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *args, ngx_uint_t nargs, ngx_uint_t op, ngx_uint_t after)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_str_t                    uri = ngx_string("/_oidc_redis");
    u_char                      *p;
    size_t                       len;
    ngx_uint_t                   i;

    len = 1 + NGX_INT_T_LEN + 2;
    for (i = 0; i < nargs; i++) {
        len += ngx_http_oidc_resp_len(args[i].len);
    }

    ctx->redis_cmd.data = ngx_pnalloc(r->pool, len);
    if (ctx->redis_cmd.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_sprintf(ctx->redis_cmd.data, "*%ui" CRLF, nargs);
    for (i = 0; i < nargs; i++) {
        p = ngx_http_oidc_resp_bulk(p, &args[i]);
    }

    ctx->redis_cmd.len = p - ctx->redis_cmd.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_oidc_redis_done;
    psr->data    = NULL;

    ctx->redis_op      = op;
    ctx->redis_after   = after;
    ctx->redis_handled = 0;
    ngx_str_null(&ctx->redis_value);

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->waiting = 1;

    return NGX_AGAIN;
}


static void
ngx_http_oidc_redis_key(ngx_http_request_t *r, const char *prefix,
    ngx_str_t *value, ngx_str_t *key)
{
    size_t  plen = ngx_strlen(prefix);

    key->data = ngx_pnalloc(r->pool, plen + value->len);
    if (key->data == NULL) {
        ngx_str_null(key);
        return;
    }

    ngx_memcpy(key->data, prefix, plen);
    ngx_memcpy(key->data + plen, value->data, value->len);
    key->len = plen + value->len;
}


static ngx_int_t
ngx_http_oidc_redis_load(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t  args[2];

    ngx_str_set(&args[0], "GET");
    ngx_http_oidc_redis_key(r, "oidc:s:", &ctx->sid, &args[1]);

    if (args[1].len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_oidc_redis_call(r, ctx, args, 2, OIDC_REDIS_LOAD,
                                    OIDC_AFTER_RESUME);
}


static ngx_int_t
ngx_http_oidc_redis_save(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *record, time_t ttl, ngx_uint_t after)
{
    ngx_str_t  args[11];
    u_char     ttl_buf[NGX_TIME_T_LEN];

    ngx_str_set(&args[0], "EVAL");
    args[1] = ngx_http_oidc_save_script;
    ngx_str_set(&args[2], "3");

    ngx_http_oidc_redis_key(r, "oidc:s:", &ctx->sid, &args[3]);
    ngx_http_oidc_redis_key(r, "oidc:x:sid:", &ctx->oidc_sid, &args[4]);
    ngx_http_oidc_redis_key(r, "oidc:x:sub:", &ctx->claims.sub, &args[5]);

    if (args[3].len == 0 || args[4].len == 0 || args[5].len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    args[6].data = ttl_buf;
    args[6].len  = ngx_sprintf(ttl_buf, "%T", ttl) - ttl_buf;
    args[7]      = *record;
    args[8]      = ctx->sid;
    args[9]      = ctx->oidc_sid;
    args[10]     = ctx->claims.sub;

    return ngx_http_oidc_redis_call(r, ctx, args, 11, OIDC_REDIS_SAVE, after);
}


static ngx_int_t
ngx_http_oidc_redis_delete(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_uint_t after)
{
    ngx_str_t  args[2];

    ngx_str_set(&args[0], "DEL");
    ngx_http_oidc_redis_key(r, "oidc:s:", &ctx->sid, &args[1]);

    if (args[1].len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_oidc_redis_call(r, ctx, args, 2, OIDC_REDIS_DELETE, after);
}


/*
 * Delete every session indexed under `key` (back-channel / front-channel
 * logout).  A Lua script keeps it to a single round trip.
 */
static ngx_int_t
ngx_http_oidc_redis_purge(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *index_key, ngx_uint_t after)
{
    ngx_str_t  args[4];

    ngx_str_set(&args[0], "EVAL");
    args[1] = ngx_http_oidc_purge_script;
    ngx_str_set(&args[2], "1");
    args[3] = *index_key;

    return ngx_http_oidc_redis_call(r, ctx, args, 4, OIDC_REDIS_PURGE, after);
}


/* ------------------------------------------------------------------------ *
 *  Shared memory session store (oidc_session_store <size>)
 *
 *  Keeping the session server side is what makes the ID token, the access
 *  token and the refresh token usable after the login request: they are far
 *  too large, and the refresh token too sensitive, to travel in a cookie.
 *  With a store enabled the cookie carries nothing but a 256 bit random
 *  session id.
 *
 *  Each entry holds the serialised record plus the "sub" and "sid" claims,
 *  which back-channel and front-channel logout use to find the sessions of
 *  one subject.
 * ------------------------------------------------------------------------ */

typedef struct {
    ngx_rbtree_node_t  node;          /* node.key = crc32 of the session id */
    ngx_queue_t        queue;         /* LRU, most recently used first */
    time_t             expires;
    u_char             sid[64];
    u_short            record_len;
    u_short            sub_len;
    u_short            oidc_sid_len;
    u_char             data[1];       /* record || sub || oidc_sid */
} ngx_http_oidc_sess_t;


typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;
} ngx_http_oidc_shctx_t;


typedef struct {
    ngx_http_oidc_shctx_t  *sh;
    ngx_slab_pool_t        *shpool;
} ngx_http_oidc_shm_t;


static void
ngx_http_oidc_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t     **p;
    ngx_http_oidc_sess_t   *sn, *snt;

    for ( ;; ) {

        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else {
            sn  = (ngx_http_oidc_sess_t *) node;
            snt = (ngx_http_oidc_sess_t *) temp;

            p = (ngx_memcmp(sn->sid, snt->sid, sizeof(sn->sid)) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left   = sentinel;
    node->right  = sentinel;
    ngx_rbt_red(node);
}


static ngx_int_t
ngx_http_oidc_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_oidc_shm_t  *octx = shm_zone->data;
    ngx_http_oidc_shm_t  *oshm = data;   /* previous cycle */

    if (oshm) {
        octx->sh     = oshm->sh;
        octx->shpool = oshm->shpool;
        return NGX_OK;
    }

    octx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        octx->sh = octx->shpool->data;
        return NGX_OK;
    }

    octx->sh = ngx_slab_alloc(octx->shpool, sizeof(ngx_http_oidc_shctx_t));
    if (octx->sh == NULL) {
        return NGX_ERROR;
    }

    octx->shpool->data = octx->sh;

    ngx_rbtree_init(&octx->sh->rbtree, &octx->sh->sentinel,
                    ngx_http_oidc_rbtree_insert_value);
    ngx_queue_init(&octx->sh->queue);

    octx->shpool->log_ctx = ngx_slab_alloc(octx->shpool,
                                           sizeof(" in OIDC session store"));
    if (octx->shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_sprintf(octx->shpool->log_ctx, "%s%Z", " in OIDC session store");

    return NGX_OK;
}


/* The shared pool mutex must be held by the caller. */
static ngx_http_oidc_sess_t *
ngx_http_oidc_sess_lookup(ngx_http_oidc_shctx_t *sh, ngx_str_t *sid)
{
    ngx_rbtree_node_t     *node, *sentinel;
    ngx_http_oidc_sess_t  *sess;
    uint32_t               hash;
    ngx_int_t              rc;

    if (sid->len != 64) {
        return NULL;
    }

    hash     = ngx_crc32_short(sid->data, sid->len);
    node     = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        sess = (ngx_http_oidc_sess_t *) node;

        rc = ngx_memcmp(sid->data, sess->sid, sizeof(sess->sid));
        if (rc == 0) {
            return sess;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


static void
ngx_http_oidc_sess_remove(ngx_http_oidc_shm_t *shm, ngx_http_oidc_sess_t *sess)
{
    ngx_queue_remove(&sess->queue);
    ngx_rbtree_delete(&shm->sh->rbtree, &sess->node);
    ngx_slab_free_locked(shm->shpool, sess);
}


/*
 * Drop expired sessions, oldest first.  When `force` is set one live session
 * is evicted as well so that a new one can be stored in a full zone.
 */
static void
ngx_http_oidc_sess_expire(ngx_http_oidc_shm_t *shm, ngx_uint_t force)
{
    ngx_queue_t           *q;
    ngx_http_oidc_sess_t  *sess;
    time_t                 now = ngx_time();
    ngx_uint_t             i;

    for (i = 0; i < 16; i++) {

        if (ngx_queue_empty(&shm->sh->queue)) {
            return;
        }

        q    = ngx_queue_last(&shm->sh->queue);
        sess = ngx_queue_data(q, ngx_http_oidc_sess_t, queue);

        if (!force && sess->expires > now) {
            return;
        }

        ngx_http_oidc_sess_remove(shm, sess);

        if (force) {
            return;
        }
    }
}


static ngx_int_t
ngx_http_oidc_sess_store(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_str_t *sid, ngx_str_t *record, ngx_str_t *sub, ngx_str_t *oidc_sid,
    time_t expires)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;
    size_t                 size;
    u_char                *p;
    ngx_uint_t             tries;

    if (sid->len != 64
        || record->len > OIDC_MAX_TOKEN_LEN * 4
        || sub->len > 1024 || oidc_sid->len > 1024)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: session data is too large for the store");
        return NGX_ERROR;
    }

    size = offsetof(ngx_http_oidc_sess_t, data)
         + record->len + sub->len + oidc_sid->len;

    ngx_shmtx_lock(&shm->shpool->mutex);

    sess = ngx_http_oidc_sess_lookup(shm->sh, sid);
    if (sess != NULL) {
        ngx_http_oidc_sess_remove(shm, sess);
    }

    ngx_http_oidc_sess_expire(shm, 0);

    for (tries = 0; ; tries++) {
        sess = ngx_slab_alloc_locked(shm->shpool, size);
        if (sess != NULL) {
            break;
        }

        if (tries >= 8 || ngx_queue_empty(&shm->sh->queue)) {
            ngx_shmtx_unlock(&shm->shpool->mutex);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: the session store is full, "
                          "increase oidc_session_store");
            return NGX_ERROR;
        }

        ngx_http_oidc_sess_expire(shm, 1);
    }

    sess->node.key = ngx_crc32_short(sid->data, sid->len);
    sess->expires  = expires;
    ngx_memcpy(sess->sid, sid->data, sizeof(sess->sid));

    sess->record_len   = (u_short) record->len;
    sess->sub_len      = (u_short) sub->len;
    sess->oidc_sid_len = (u_short) oidc_sid->len;

    p = sess->data;
    p = ngx_cpymem(p, record->data, record->len);
    p = ngx_cpymem(p, sub->data, sub->len);
    ngx_memcpy(p, oidc_sid->data, oidc_sid->len);

    ngx_rbtree_insert(&shm->sh->rbtree, &sess->node);
    ngx_queue_insert_head(&shm->sh->queue, &sess->queue);

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_OK;
}


/*
 * Copy a stored record into the request pool.  Returns NGX_DECLINED when the
 * session is unknown or has expired.
 */
static ngx_int_t
ngx_http_oidc_sess_load(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_str_t *sid, ngx_str_t *record)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;
    ngx_int_t              rc = NGX_DECLINED;

    ngx_shmtx_lock(&shm->shpool->mutex);

    sess = ngx_http_oidc_sess_lookup(shm->sh, sid);

    if (sess == NULL) {
        goto done;
    }

    if (sess->expires <= ngx_time()) {
        ngx_http_oidc_sess_remove(shm, sess);
        goto done;
    }

    record->data = ngx_pnalloc(r->pool, sess->record_len);
    if (record->data == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    ngx_memcpy(record->data, sess->data, sess->record_len);
    record->len = sess->record_len;

    /* Refresh the LRU position. */
    ngx_queue_remove(&sess->queue);
    ngx_queue_insert_head(&shm->sh->queue, &sess->queue);

    rc = NGX_OK;

done:

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return rc;
}


static void
ngx_http_oidc_sess_delete(ngx_shm_zone_t *zone, ngx_str_t *sid)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;

    ngx_shmtx_lock(&shm->shpool->mutex);

    sess = ngx_http_oidc_sess_lookup(shm->sh, sid);
    if (sess != NULL) {
        ngx_http_oidc_sess_remove(shm, sess);
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);
}


/*
 * Delete every session of one subject or one provider side session id.
 * Logout is rare, so a linear walk of the LRU queue is preferred over a
 * second index in shared memory.
 */
static ngx_uint_t
ngx_http_oidc_sess_purge(ngx_shm_zone_t *zone, ngx_str_t *sub,
    ngx_str_t *oidc_sid)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;
    ngx_queue_t           *q, *prev;
    u_char                *p;
    ngx_uint_t             n = 0;

    ngx_shmtx_lock(&shm->shpool->mutex);

    for (q = ngx_queue_last(&shm->sh->queue);
         q != ngx_queue_sentinel(&shm->sh->queue);
         q = prev)
    {
        prev = ngx_queue_prev(q);
        sess = ngx_queue_data(q, ngx_http_oidc_sess_t, queue);

        p = sess->data + sess->record_len;

        if (oidc_sid->len
            && sess->oidc_sid_len == oidc_sid->len
            && ngx_memcmp(p + sess->sub_len, oidc_sid->data,
                          oidc_sid->len) == 0)
        {
            ngx_http_oidc_sess_remove(shm, sess);
            n++;
            continue;
        }

        if (sub->len
            && sess->sub_len == sub->len
            && ngx_memcmp(p, sub->data, sub->len) == 0)
        {
            ngx_http_oidc_sess_remove(shm, sess);
            n++;
        }
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return n;
}


/* ------------------------------------------------------------------------ *
 *  Discovery
 * ------------------------------------------------------------------------ */

/*
 * Copy the subrequest response body (kept in memory thanks to
 * NGX_HTTP_SUBREQUEST_IN_MEMORY) into a NUL terminated buffer.
 */
static ngx_int_t
ngx_http_oidc_subrequest_body(ngx_http_request_t *r, ngx_str_t *body)
{
    if (r->upstream == NULL || r->upstream->buffer.start == NULL) {
        return NGX_ERROR;
    }

    body->len = r->upstream->buffer.last - r->upstream->buffer.pos;
    if (body->len == 0) {
        return NGX_ERROR;
    }

    body->data = ngx_pnalloc(r->pool, body->len + 1);
    if (body->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(body->data, r->upstream->buffer.pos, body->len);
    body->data[body->len] = '\0';

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_parse_discovery_json(ngx_http_request_t *r, ngx_pool_t *pool,
    const u_char *data, size_t len,
    ngx_http_oidc_provider_metadata_t *metadata)
{
    json_t       *root, *v;
    json_error_t  error;
    ngx_int_t     rc = NGX_ERROR;

    root = json_loadb((const char *) data, len, 0, &error);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: discovery JSON parse error: %s", error.text);
        return NGX_ERROR;
    }

    if (!json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: discovery document is not a JSON object");
        goto done;
    }

#define OIDC_DISCOVERY_FIELD(field, name, required)                           \
    v = json_object_get(root, name);                                          \
    if (json_is_string(v)) {                                                  \
        if (ngx_http_oidc_str_copy(pool, &metadata->field,                    \
                                   json_string_value(v),                      \
                                   ngx_strlen(json_string_value(v)))          \
            != NGX_OK)                                                        \
        {                                                                     \
            goto done;                                                        \
        }                                                                     \
    } else if (required) {                                                    \
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,                     \
                      "OIDC: discovery document has no \"%s\"", name);        \
        goto done;                                                            \
    }

    OIDC_DISCOVERY_FIELD(issuer,                "issuer",                 1)
    OIDC_DISCOVERY_FIELD(authorization_endpoint, "authorization_endpoint", 1)
    OIDC_DISCOVERY_FIELD(token_endpoint,        "token_endpoint",         1)
    OIDC_DISCOVERY_FIELD(jwks_uri,              "jwks_uri",               1)
    OIDC_DISCOVERY_FIELD(userinfo_endpoint,     "userinfo_endpoint",      0)
    OIDC_DISCOVERY_FIELD(end_session_endpoint,  "end_session_endpoint",   0)
    OIDC_DISCOVERY_FIELD(introspection_endpoint, "introspection_endpoint", 0)

#undef OIDC_DISCOVERY_FIELD

    rc = NGX_OK;

done:

    json_decref(root);

    return rc;
}


/*
 * Discovery subrequest completion handler.
 *
 * On success the metadata is cached in the location's own pool.  The previous
 * generation is released here; no request can still be pointing into it
 * because the access handler always works on a request-pool copy.
 */
static ngx_int_t
ngx_http_oidc_discovery_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t                 *pr = r->parent;
    ngx_http_oidc_ctx_t                *ctx;
    ngx_http_oidc_loc_conf_t           *lcf;
    ngx_http_oidc_provider_metadata_t  *metadata;
    ngx_http_oidc_cache_t              *cache;
    ngx_pool_t                         *pool, *old;
    ngx_str_t                           body, issuer, provider;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->discovery_handled || ctx->done) {
        return rc;
    }
    ctx->discovery_handled = 1;

    ctx->waiting = 0;

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: discovery request failed, status: %ui",
                      r->headers_out.status);
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    if (ngx_http_oidc_subrequest_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: discovery response has no body");
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    pool = ngx_create_pool(1024, ngx_cycle->log);
    if (pool == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    metadata = ngx_pcalloc(pool, sizeof(ngx_http_oidc_provider_metadata_t));
    if (metadata == NULL) {
        ngx_destroy_pool(pool);
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ngx_http_oidc_parse_discovery_json(pr, pool, body.data, body.len,
                                           metadata) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    /*
     * OpenID Connect Discovery 1.0 section 4.3: the issuer returned in the
     * document MUST match the issuer the document was requested from.
     */
    issuer   = metadata->issuer;
    provider = lcf->oidc_provider;
    ngx_http_oidc_trim_slash(&issuer);
    ngx_http_oidc_trim_slash(&provider);

    if (issuer.len != provider.len
        || ngx_strncmp(issuer.data, provider.data, issuer.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: discovery issuer \"%V\" does not match "
                      "oidc_provider \"%V\"", &metadata->issuer,
                      &lcf->oidc_provider);
        ngx_destroy_pool(pool);
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    cache = lcf->cache;
    old   = cache->pool;

    cache->metadata = metadata;
    cache->pool     = pool;
    cache->expires  = ngx_time() + OIDC_DISCOVERY_TTL;

    if (old != NULL) {
        ngx_destroy_pool(old);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "OIDC: discovery cached for \"%V\"", &lcf->oidc_provider);

    /*
     * Do not set ctx->done: the parent simply resumes its phases and the
     * access handler continues with the freshly cached metadata.
     */
    pr->write_event_handler = ngx_http_core_run_phases;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_start_discovery(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_str_t                    uri = ngx_string("/_oidc_discovery");
    ngx_str_t                    provider = lcf->oidc_provider;
    static const char           *path = "/.well-known/openid-configuration";
    size_t                       len;

    ngx_http_oidc_trim_slash(&provider);

    len = provider.len + ngx_strlen(path);
    ctx->discovery_url.data = ngx_pnalloc(r->pool, len + 1);
    if (ctx->discovery_url.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->discovery_url.len = ngx_snprintf(ctx->discovery_url.data, len + 1,
                                          "%V%s", &provider, path)
                             - ctx->discovery_url.data;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_oidc_discovery_handler;
    psr->data    = NULL;

    ctx->discovery_attempted = 1;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->waiting = 1;

    return NGX_AGAIN;
}


/* ------------------------------------------------------------------------ *
 *  Authorization request
 * ------------------------------------------------------------------------ */

/*
 * Base64URL encode (RFC 4648 section 5, no padding).
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
 * PKCE code_challenge = BASE64URL(SHA256(code_verifier)).
 */
static size_t
ngx_http_oidc_pkce_challenge(u_char *dst, const u_char *verifier,
    size_t verifier_len)
{
    u_char hash[32];

    SHA256(verifier, verifier_len, hash);

    return ngx_http_oidc_base64url_encode(dst, hash, sizeof(hash));
}


static ngx_int_t
ngx_http_oidc_random_hex(u_char *dst, size_t bytes)
{
    u_char raw[32];

    if (bytes > sizeof(raw)) {
        return NGX_ERROR;
    }

    if (RAND_bytes(raw, (int) bytes) != 1) {
        return NGX_ERROR;
    }

    ngx_hex_dump(dst, raw, bytes);

    return NGX_OK;
}


/*
 * Build the authorization request and redirect the browser to the IdP.
 */
static ngx_int_t
ngx_http_oidc_redirect_to_idp(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_table_elt_t  *location;
    ngx_str_t        *auth_endpoint = &ctx->metadata->authorization_endpoint;
    ngx_str_t         state, nonce, verifier, return_to, esc_return_to;
    ngx_str_t         extra = ngx_null_string;
    u_char            state_buf[64], nonce_buf[64], verifier_buf[64];
    u_char            challenge[43];
    size_t            challenge_len, len;
    u_char           *p;
    ngx_uint_t        has_query;

    if (auth_endpoint->len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
     * oidc_auth_request_args lets a deployment add parameters such as
     * prompt=select_account or login_hint=... to the authorization request.
     */
    if (lcf->auth_args != NULL
        && ngx_http_complex_value(r, lcf->auth_args, &extra) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_oidc_random_hex(state_buf, 32) != NGX_OK
        || ngx_http_oidc_random_hex(nonce_buf, 32) != NGX_OK
        || ngx_http_oidc_random_hex(verifier_buf, 32) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: RAND_bytes() failed");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    state.data    = state_buf;    state.len    = sizeof(state_buf);
    nonce.data    = nonce_buf;    nonce.len    = sizeof(nonce_buf);
    verifier.data = verifier_buf; verifier.len = sizeof(verifier_buf);

    challenge_len = ngx_http_oidc_pkce_challenge(challenge, verifier.data,
                                                 verifier.len);

    /* ---- authorization endpoint URL ---- */

    has_query = (ngx_strlchr(auth_endpoint->data,
                             auth_endpoint->data + auth_endpoint->len, '?')
                 != NULL);

    len = auth_endpoint->len + 1
        + sizeof("response_type=code") - 1
        + sizeof("&scope=") - 1 + ngx_http_oidc_escaped_len(&lcf->oidc_scope)
        + sizeof("&client_id=") - 1 + ngx_http_oidc_escaped_len(&lcf->client_id)
        + sizeof("&redirect_uri=") - 1
            + ngx_http_oidc_escaped_len(&lcf->redirect_uri)
        + sizeof("&state=") - 1 + state.len
        + sizeof("&nonce=") - 1 + nonce.len
        + sizeof("&code_challenge=") - 1 + challenge_len
        + sizeof("&code_challenge_method=S256") - 1
        + (extra.len ? 1 + extra.len : 0);

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

    p = ngx_cpymem(location->value.data, auth_endpoint->data,
                   auth_endpoint->len);
    *p++ = has_query ? '&' : '?';

    p = ngx_cpymem(p, "response_type=code", sizeof("response_type=code") - 1);

    p = ngx_cpymem(p, "&scope=", sizeof("&scope=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->oidc_scope);

    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->client_id);

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->redirect_uri);

    p = ngx_cpymem(p, "&state=", sizeof("&state=") - 1);
    p = ngx_cpymem(p, state.data, state.len);

    p = ngx_cpymem(p, "&nonce=", sizeof("&nonce=") - 1);
    p = ngx_cpymem(p, nonce.data, nonce.len);

    p = ngx_cpymem(p, "&code_challenge=", sizeof("&code_challenge=") - 1);
    p = ngx_cpymem(p, challenge, challenge_len);

    p = ngx_cpymem(p, "&code_challenge_method=S256",
                   sizeof("&code_challenge_method=S256") - 1);

    if (extra.len) {
        *p++ = '&';
        p = ngx_cpymem(p, extra.data, extra.len);
    }

    location->value.len = p - location->value.data;

    /* ---- transaction cookies ---- */

    return_to.len  = r->uri.len + (r->args.len ? 1 + r->args.len : 0);
    if (return_to.len > OIDC_RETURN_TO_MAX) {
        return_to.len = r->uri.len;
    }

    return_to.data = ngx_pnalloc(r->pool, return_to.len + 1);
    if (return_to.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(return_to.data, r->uri.data, r->uri.len);
    if (return_to.len > r->uri.len) {
        *p++ = '?';
        p = ngx_cpymem(p, r->args.data, r->args.len);
    }
    return_to.len = p - return_to.data;

    /*
     * The URI is stored percent-encoded: NGINX hands us the decoded form,
     * which may contain characters that are not valid inside a cookie value.
     */
    esc_return_to.len  = ngx_http_oidc_escaped_len(&return_to);
    esc_return_to.data = ngx_pnalloc(r->pool, esc_return_to.len);
    if (esc_return_to.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    (void) ngx_http_oidc_escape(esc_return_to.data, &return_to);

    if (ngx_http_oidc_add_cookie(r, "oidc_state", sizeof("oidc_state") - 1,
                                 &state, 600) != NGX_OK
        || ngx_http_oidc_add_cookie(r, "oidc_nonce", sizeof("oidc_nonce") - 1,
                                    &nonce, 600) != NGX_OK
        || ngx_http_oidc_add_cookie(r, "oidc_pkce_verifier",
                                    sizeof("oidc_pkce_verifier") - 1,
                                    &verifier, 600) != NGX_OK
        || ngx_http_oidc_add_cookie(r, "oidc_return_to",
                                    sizeof("oidc_return_to") - 1,
                                    &esc_return_to, 600) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status   = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.location = location;

    return NGX_HTTP_MOVED_TEMPORARILY;
}


/* ------------------------------------------------------------------------ *
 *  Token request
 * ------------------------------------------------------------------------ */

/*
 * Build the client assertion used by client_secret_jwt and private_key_jwt
 * (RFC 7523 section 2.2).  It is created once per request and reused by the
 * token and introspection calls.
 */
static ngx_int_t
ngx_http_oidc_client_assertion(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    jwt_t       *jwt = NULL;
    jwt_alg_t    alg;
    ngx_str_t   *key;
    const char  *enc;
    char        *token;
    u_char       jti[65];
    time_t       now = ngx_time();
    ngx_int_t    rc = NGX_ERROR;

    if (ctx->client_assertion.len) {
        return NGX_OK;
    }

    key = (lcf->client_auth == OIDC_CLIENT_AUTH_PRIVATE_JWT)
          ? &lcf->client_jwt_key : &lcf->client_secret;

    if (key->len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: no key configured for the chosen "
                      "oidc_client_auth method");
        return NGX_ERROR;
    }

    if (lcf->client_jwt_alg.len) {
        alg = jwt_str_alg((const char *) lcf->client_jwt_alg.data);

    } else {
        alg = (lcf->client_auth == OIDC_CLIENT_AUTH_PRIVATE_JWT)
              ? JWT_ALG_RS256 : JWT_ALG_HS256;
    }

    if (alg == JWT_ALG_INVAL || alg == JWT_ALG_NONE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: unsupported oidc_client_jwt_alg \"%V\"",
                      &lcf->client_jwt_alg);
        return NGX_ERROR;
    }

    if (ngx_http_oidc_random_hex(jti, 32) != NGX_OK) {
        return NGX_ERROR;
    }
    jti[64] = '\0';

    if (jwt_new(&jwt) != 0 || jwt == NULL) {
        return NGX_ERROR;
    }

    if (jwt_set_alg(jwt, alg, key->data, (int) key->len) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the client assertion key was rejected by libjwt");
        goto done;
    }

    if (lcf->client_jwt_kid.len
        && jwt_add_header(jwt, "kid",
                          (const char *) lcf->client_jwt_kid.data) != 0)
    {
        goto done;
    }

    if (jwt_add_grant(jwt, "iss", (const char *) lcf->client_id.data) != 0
        || jwt_add_grant(jwt, "sub", (const char *) lcf->client_id.data) != 0
        || jwt_add_grant(jwt, "aud",
               (const char *) ctx->metadata->token_endpoint.data) != 0
        || jwt_add_grant(jwt, "jti", (const char *) jti) != 0
        || jwt_add_grant_int(jwt, "iat", (long) now) != 0
        || jwt_add_grant_int(jwt, "exp", (long) (now + 60)) != 0)
    {
        goto done;
    }

    token = jwt_encode_str(jwt);
    if (token == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: could not sign the client assertion");
        goto done;
    }

    enc = token;
    rc = ngx_http_oidc_str_copy(r->pool, &ctx->client_assertion, enc,
                                ngx_strlen(enc));
    jwt_free_str(token);

done:

    jwt_free(jwt);

    return rc;
}


/*
 * Everything the chosen client authentication method adds to a request body.
 * With client_secret_basic nothing is added: the credentials travel in the
 * Authorization header instead.
 */
static ngx_int_t
ngx_http_oidc_client_auth_prepare(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    if (lcf->client_auth == OIDC_CLIENT_AUTH_SECRET_JWT
        || lcf->client_auth == OIDC_CLIENT_AUTH_PRIVATE_JWT)
    {
        return ngx_http_oidc_client_assertion(r, lcf, ctx);
    }

    return NGX_OK;
}


static size_t
ngx_http_oidc_client_auth_len(ngx_http_oidc_loc_conf_t *lcf,
    ngx_http_oidc_ctx_t *ctx)
{
    switch (lcf->client_auth) {

    case OIDC_CLIENT_AUTH_POST:
        return lcf->client_post.len;

    case OIDC_CLIENT_AUTH_SECRET_JWT:
    case OIDC_CLIENT_AUTH_PRIVATE_JWT:
        return sizeof(OIDC_ASSERTION_TYPE) - 1
               + ngx_http_oidc_escaped_len(&ctx->client_assertion);

    default:
        return 0;
    }
}


static u_char *
ngx_http_oidc_client_auth_append(u_char *p, ngx_http_oidc_loc_conf_t *lcf,
    ngx_http_oidc_ctx_t *ctx)
{
    switch (lcf->client_auth) {

    case OIDC_CLIENT_AUTH_POST:
        if (lcf->client_post.len) {
            p = ngx_cpymem(p, lcf->client_post.data, lcf->client_post.len);
        }
        break;

    case OIDC_CLIENT_AUTH_SECRET_JWT:
    case OIDC_CLIENT_AUTH_PRIVATE_JWT:
        p = ngx_cpymem(p, OIDC_ASSERTION_TYPE,
                       sizeof(OIDC_ASSERTION_TYPE) - 1);
        p = ngx_http_oidc_escape(p, &ctx->client_assertion);
        break;

    default:
        break;
    }

    return p;
}


/*
 * Start a subrequest to the token endpoint.
 *
 * The request parameters are published through $oidc_token_body (consumed by
 * proxy_set_body) and, for client_secret_basic, the credentials through
 * $oidc_token_basic.  Nothing is passed as subrequest arguments, so neither
 * the authorization code nor the client secret ever reaches a request line,
 * an access log or an error log.
 */
static ngx_int_t
ngx_http_oidc_send_token_request(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, ngx_uint_t phase)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_str_t                    uri = ngx_string("/_oidc_token");

    ctx->token_basic = (lcf->client_auth == OIDC_CLIENT_AUTH_BASIC)
                       ? lcf->client_basic : (ngx_str_t) ngx_null_string;
    ctx->token_url   = ctx->metadata->token_endpoint;
    ctx->phase       = phase;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_oidc_token_handler;
    psr->data    = NULL;

    /* A retried step must run its completion handler again. */
    ctx->token_handled = 0;
    ctx->jwks_handled  = 0;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->waiting = 1;

    return NGX_AGAIN;
}


static ngx_int_t
ngx_http_oidc_start_token_request(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, ngx_str_t *code)
{
    ngx_str_t  verifier = ngx_null_string;
    size_t     len;
    u_char    *p;

    if (lcf->client_auth != OIDC_CLIENT_AUTH_PRIVATE_JWT
        && lcf->client_secret.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: oidc_client_secret is not set");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_oidc_client_auth_prepare(r, lcf, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    (void) ngx_http_oidc_get_cookie(r, "oidc_pkce_verifier",
                                    sizeof("oidc_pkce_verifier") - 1,
                                    &verifier);

    len = sizeof("grant_type=authorization_code") - 1
        + sizeof("&code=") - 1 + ngx_http_oidc_escaped_len(code)
        + sizeof("&redirect_uri=") - 1
            + ngx_http_oidc_escaped_len(&lcf->redirect_uri)
        + sizeof("&client_id=") - 1
            + ngx_http_oidc_escaped_len(&lcf->client_id)
        + (verifier.len
           ? sizeof("&code_verifier=") - 1 + ngx_http_oidc_escaped_len(&verifier)
           : 0)
        + ngx_http_oidc_client_auth_len(lcf, ctx);

    ctx->token_body.data = ngx_pnalloc(r->pool, len);
    if (ctx->token_body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(ctx->token_body.data, "grant_type=authorization_code",
                   sizeof("grant_type=authorization_code") - 1);

    p = ngx_cpymem(p, "&code=", sizeof("&code=") - 1);
    p = ngx_http_oidc_escape(p, code);

    p = ngx_cpymem(p, "&redirect_uri=", sizeof("&redirect_uri=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->redirect_uri);

    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->client_id);

    if (verifier.len) {
        p = ngx_cpymem(p, "&code_verifier=", sizeof("&code_verifier=") - 1);
        p = ngx_http_oidc_escape(p, &verifier);
    }

    p = ngx_http_oidc_client_auth_append(p, lcf, ctx);

    ctx->token_body.len = p - ctx->token_body.data;
    ctx->token_attempted = 1;

    return ngx_http_oidc_send_token_request(r, lcf, ctx, OIDC_PHASE_LOGIN);
}


/*
 * Renew the tokens of an existing session with the refresh token
 * (RFC 6749 section 6).
 */
static ngx_int_t
ngx_http_oidc_start_refresh_request(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    size_t   len;
    u_char  *p;

    if (ngx_http_oidc_client_auth_prepare(r, lcf, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("grant_type=refresh_token") - 1
        + sizeof("&refresh_token=") - 1
            + ngx_http_oidc_escaped_len(&ctx->refresh_token)
        + sizeof("&client_id=") - 1
            + ngx_http_oidc_escaped_len(&lcf->client_id)
        + ngx_http_oidc_client_auth_len(lcf, ctx);

    ctx->token_body.data = ngx_pnalloc(r->pool, len);
    if (ctx->token_body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(ctx->token_body.data, "grant_type=refresh_token",
                   sizeof("grant_type=refresh_token") - 1);

    p = ngx_cpymem(p, "&refresh_token=", sizeof("&refresh_token=") - 1);
    p = ngx_http_oidc_escape(p, &ctx->refresh_token);

    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->client_id);

    p = ngx_http_oidc_client_auth_append(p, lcf, ctx);

    ctx->token_body.len = p - ctx->token_body.data;
    ctx->refresh_attempted = 1;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "OIDC: refreshing the access token");

    return ngx_http_oidc_send_token_request(r, lcf, ctx, OIDC_PHASE_REFRESH);
}


/*
 * A refresh attempt that fails is not an error for the user: the session is
 * dropped and the request falls back to a full re-authentication.
 */
static void
ngx_http_oidc_refresh_failed(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf)
{
    if (ctx->sid.len) {
        if (mcf->store == OIDC_STORE_SHM) {
            ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);

        } else if (mcf->store == OIDC_STORE_REDIS) {
            /*
             * Best effort: the entry expires on its own, and the session is
             * already marked invalid for this request.
             */
            (void) ngx_http_oidc_redis_delete(r, ctx, OIDC_AFTER_RESUME);
            ctx->session_valid = 0;
            return;
        }
    }

    ctx->session_valid = 0;
    ctx->waiting = 0;
    r->write_event_handler = ngx_http_core_run_phases;
}


/*
 * Write the current tokens and claims back to the store, keeping the same
 * session id, and hand the browser a cookie with a fresh Max-Age.
 */
static ngx_int_t
ngx_http_oidc_renew_session(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf, ngx_http_oidc_loc_conf_t *lcf)
{
    ngx_int_t  rc;

    rc = ngx_http_oidc_save_session(r, ctx, mcf, lcf, ngx_time(),
                                    OIDC_AFTER_REFRESH);
    if (rc != NGX_OK) {
        return rc;                    /* NGX_AGAIN or NGX_ERROR */
    }

    return ngx_http_oidc_add_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                    &ctx->pending_cookie,
                                    ngx_http_oidc_session_lifetime(lcf));
}


/*
 * Token subrequest completion handler.  Serves both the authorization code
 * grant (login) and the refresh token grant.
 */
static ngx_int_t
ngx_http_oidc_token_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t        *pr = r->parent;
    ngx_http_oidc_ctx_t       *ctx;
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_http_oidc_main_conf_t *mcf;
    ngx_str_t                  body;
    json_t                    *root, *v;
    json_error_t               error;
    ngx_uint_t                 refreshing;
    ngx_int_t                  status = NGX_HTTP_BAD_GATEWAY;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL || mcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->token_handled || ctx->done) {
        return rc;
    }
    ctx->token_handled = 1;

    refreshing = (ctx->phase == OIDC_PHASE_REFRESH);

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_uint_t level = refreshing ? NGX_LOG_WARN : NGX_LOG_ERR;

        ngx_log_error(level, r->connection->log, 0,
                      "OIDC: token request failed, status: %ui",
                      r->headers_out.status);
        goto failed;
    }

    if (ngx_http_oidc_subrequest_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: token response has no body");
        goto failed;
    }

    root = json_loadb((const char *) body.data, body.len, 0, &error);
    if (root == NULL || !json_is_object(root)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: token response JSON parse error: %s", error.text);
        if (root) {
            json_decref(root);
        }
        goto failed;
    }

    /* access_token / refresh_token / expires_in are all optional. */

    v = json_object_get(root, "access_token");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(pr->pool, &ctx->access_token,
                                      json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    v = json_object_get(root, "refresh_token");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(pr->pool, &ctx->refresh_token,
                                      json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    v = json_object_get(root, "expires_in");
    ctx->access_expires = json_is_integer(v)
                          ? ngx_time() + (time_t) json_integer_value(v)
                          : 0;

    v = json_object_get(root, "id_token");

    if (json_is_string(v)) {
        if (ngx_http_oidc_str_copy(pr->pool, &ctx->id_token,
                                   json_string_value(v),
                                   ngx_strlen(json_string_value(v))) != NGX_OK)
        {
            json_decref(root);
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        json_decref(root);

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "OIDC: id_token received, fetching JWKS");

        /*
         * Chain the JWKS subrequest.  ctx->waiting stays set so the parent,
         * whose phases are re-run as soon as this subrequest is finalised,
         * keeps waiting instead of finalising the request behind our back.
         */
        if (ngx_http_oidc_start_jwks_request(pr) != NGX_OK) {
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto failed;
        }

        return NGX_OK;
    }

    json_decref(root);

    if (!refreshing) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: token response has no id_token");
        goto failed;
    }

    /*
     * A refresh response without an ID token is allowed: the claims of the
     * running session stay as they are and only the tokens are renewed.
     */
    rc = ngx_http_oidc_renew_session(pr, ctx, mcf, lcf);

    if (rc == NGX_AGAIN) {
        return NGX_OK;                /* the Redis handler resumes the request */
    }

    if (rc != NGX_OK) {
        goto failed;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "OIDC: tokens refreshed");

    ctx->refreshed = 1;
    ctx->waiting   = 0;
    pr->write_event_handler = ngx_http_core_run_phases;

    return NGX_OK;

failed:

    if (refreshing) {
        ngx_http_oidc_refresh_failed(pr, ctx, mcf);
    } else {
        ngx_http_oidc_finish(pr, status);
    }

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  JWKS retrieval and ID token verification
 * ------------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_start_jwks_request(ngx_http_request_t *r)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_http_oidc_ctx_t         *ctx;
    ngx_str_t                    uri = ngx_string("/_oidc_jwks");

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->metadata == NULL
        || ctx->metadata->jwks_uri.len == 0)
    {
        return NGX_ERROR;
    }

    ctx->jwks_url = ctx->metadata->jwks_uri;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_jwks_handler;
    psr->data    = NULL;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->waiting = 1;

    return NGX_OK;
}


/*
 * Verify the ID token signature against the JWKS document.
 *
 * Returns NGX_OK and a decoded token on success.  The caller owns *jwt.
 */
static ngx_int_t
ngx_http_oidc_verify_signature(ngx_http_request_t *r, ngx_str_t *jwks_json,
    ngx_str_t *token, jwt_t **jwt)
{
    json_t       *root, *keys, *jwk, *v;
    json_error_t  jerr;
    ngx_str_t     alg, kid, pem;
    const char   *want_kty = NULL;
    const char   *kty;
    size_t        i, n;
    ngx_int_t     rc = NGX_DECLINED;
    int           jrc;

    *jwt = NULL;

    if (ngx_http_oidc_jwt_header(r, token, &alg, &kid) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: cannot decode the ID token header");
        return NGX_DECLINED;
    }

    if (ngx_http_oidc_alg_allowed(&alg, &want_kty) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token algorithm \"%V\" is not accepted", &alg);
        return NGX_DECLINED;
    }

    root = json_loadb((const char *) jwks_json->data, jwks_json->len, 0, &jerr);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JWKS JSON parse error: %s", jerr.text);
        return NGX_DECLINED;
    }

    keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JWKS document has no \"keys\" array");
        json_decref(root);
        return NGX_DECLINED;
    }

    n = json_array_size(keys);

    for (i = 0; i < n; i++) {
        jwk = json_array_get(keys, i);
        if (!json_is_object(jwk)) {
            continue;
        }

        v = json_object_get(jwk, "kty");
        if (!json_is_string(v)) {
            continue;
        }
        kty = json_string_value(v);
        if (ngx_strcmp(kty, want_kty) != 0) {
            continue;
        }

        /* Encryption keys must never be used to verify a signature. */
        v = json_object_get(jwk, "use");
        if (json_is_string(v) && ngx_strcmp(json_string_value(v), "sig") != 0) {
            continue;
        }

        /* When the token names a key, only that key may be used. */
        v = json_object_get(jwk, "kid");
        if (kid.len) {
            if (!json_is_string(v)
                || ngx_strlen(json_string_value(v)) != kid.len
                || ngx_strncmp(json_string_value(v), kid.data, kid.len) != 0)
            {
                continue;
            }
        }

        v = json_object_get(jwk, "alg");
        if (json_is_string(v)
            && (ngx_strlen(json_string_value(v)) != alg.len
                || ngx_strncmp(json_string_value(v), alg.data, alg.len) != 0))
        {
            continue;
        }

        if (ngx_strcmp(want_kty, "RSA") == 0) {
            if (oidc_jwk_rsa_to_pem(r->pool, jwk, &pem) != NGX_OK) {
                continue;
            }
        } else {
            if (oidc_jwk_ec_to_pem(r->pool, jwk, &pem) != NGX_OK) {
                continue;
            }
        }

        jrc = jwt_decode(jwt, (const char *) token->data, pem.data,
                         (int) pem.len);
        if (jrc == 0 && *jwt != NULL) {
            rc = NGX_OK;
            break;
        }

        if (*jwt != NULL) {
            jwt_free(*jwt);
            *jwt = NULL;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "OIDC: JWKS key did not verify the ID token (%d)", jrc);
    }

    json_decref(root);

    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token signature verification failed "
                      "(alg \"%V\", kid \"%V\")", &alg, &kid);
    }

    return rc;
}


/*
 * Validate the ID token claims per OpenID Connect Core 3.1.3.7.
 */
static ngx_int_t
ngx_http_oidc_validate_claims(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, json_t *payload)
{
    json_t     *v, *aud, *item;
    time_t      now = ngx_time();
    time_t      exp, iat;
    ngx_str_t   nonce_cookie = ngx_null_string;
    ngx_str_t   issuer, provider;
    const char *s;
    size_t      i, n;
    ngx_uint_t  matched;

    /* ---- iss ---- */
    v = json_object_get(payload, "iss");
    if (!json_is_string(v)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token has no iss claim");
        return NGX_DECLINED;
    }

    issuer.data = (u_char *) json_string_value(v);
    issuer.len  = ngx_strlen(issuer.data);
    provider    = ctx->metadata->issuer.len ? ctx->metadata->issuer
                                            : lcf->oidc_provider;
    ngx_http_oidc_trim_slash(&issuer);
    ngx_http_oidc_trim_slash(&provider);

    if (issuer.len != provider.len
        || ngx_strncmp(issuer.data, provider.data, issuer.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token iss \"%V\" does not match \"%V\"",
                      &issuer, &provider);
        return NGX_DECLINED;
    }

    /* ---- aud / azp ---- */
    aud = json_object_get(payload, "aud");
    matched = 0;
    n = 1;

    if (json_is_string(aud)) {
        s = json_string_value(aud);
        matched = (ngx_strlen(s) == lcf->client_id.len
                   && ngx_strncmp(s, lcf->client_id.data,
                                  lcf->client_id.len) == 0);

    } else if (json_is_array(aud)) {
        n = json_array_size(aud);
        for (i = 0; i < n; i++) {
            item = json_array_get(aud, i);
            if (!json_is_string(item)) {
                continue;
            }
            s = json_string_value(item);
            if (ngx_strlen(s) == lcf->client_id.len
                && ngx_strncmp(s, lcf->client_id.data,
                               lcf->client_id.len) == 0)
            {
                matched = 1;
                break;
            }
        }

    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token has no aud claim");
        return NGX_DECLINED;
    }

    if (!matched) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token aud does not contain oidc_client_id");
        return NGX_DECLINED;
    }

    /* With multiple audiences azp is required and must be this client. */
    if (n > 1) {
        v = json_object_get(payload, "azp");
        if (!json_is_string(v)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: ID token has multiple aud values but no azp");
            return NGX_DECLINED;
        }

        s = json_string_value(v);
        if (ngx_strlen(s) != lcf->client_id.len
            || ngx_strncmp(s, lcf->client_id.data, lcf->client_id.len) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: ID token azp is not oidc_client_id");
            return NGX_DECLINED;
        }
    }

    /* ---- exp / iat ---- */
    v = json_object_get(payload, "exp");
    if (!json_is_integer(v)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token has no exp claim");
        return NGX_DECLINED;
    }

    exp = (time_t) json_integer_value(v);
    if (exp + OIDC_CLOCK_SKEW < now) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token expired at %T (now %T)", exp, now);
        return NGX_DECLINED;
    }

    v = json_object_get(payload, "iat");
    if (json_is_integer(v)) {
        iat = (time_t) json_integer_value(v);
        if (iat - OIDC_CLOCK_SKEW > now) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: ID token iat %T is in the future", iat);
            return NGX_DECLINED;
        }
    }

    /*
     * ---- nonce / sub ----
     *
     * The nonce belongs to the authorization request, so it is only present
     * on a login.  An ID token obtained through a refresh must instead keep
     * the same subject as the session it renews (OIDC Core 12.2).
     */
    if (ctx->phase == OIDC_PHASE_REFRESH) {

        v = json_object_get(payload, "sub");
        if (!json_is_string(v)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: the refreshed ID token has no sub claim");
            return NGX_DECLINED;
        }

        s = json_string_value(v);
        if (ctx->claims.sub.len == 0
            || ngx_strlen(s) != ctx->claims.sub.len
            || ngx_strncmp(s, ctx->claims.sub.data, ctx->claims.sub.len) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: the refreshed ID token has a different sub");
            return NGX_DECLINED;
        }

        return NGX_OK;
    }

    (void) ngx_http_oidc_get_cookie(r, "oidc_nonce", sizeof("oidc_nonce") - 1,
                                    &nonce_cookie);

    v = json_object_get(payload, "nonce");
    if (nonce_cookie.len == 0 || !json_is_string(v)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token nonce is missing");
        return NGX_DECLINED;
    }

    s = json_string_value(v);
    if (ngx_strlen(s) != nonce_cookie.len
        || CRYPTO_memcmp(s, nonce_cookie.data, nonce_cookie.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token nonce does not match");
        return NGX_DECLINED;
    }

    return NGX_OK;
}


/*
 * JWKS subrequest completion handler: verify the ID token, extract the claims
 * and either chain the UserInfo request or issue the session cookie.
 */
static ngx_int_t
ngx_http_oidc_jwks_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t        *pr = r->parent;
    ngx_http_oidc_ctx_t       *ctx;
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_http_oidc_main_conf_t *mcf;
    ngx_str_t                  body;
    jwt_t                     *jwt = NULL;
    char                      *grants;
    json_t                    *payload;
    json_error_t               jerr;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL || mcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->jwks_handled || ctx->done) {
        return rc;
    }
    ctx->jwks_handled = 1;

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JWKS request failed, status: %ui",
                      r->headers_out.status);
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    if (ngx_http_oidc_subrequest_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: JWKS response has no body");
        ngx_http_oidc_finish(pr, NGX_HTTP_BAD_GATEWAY);
        return NGX_OK;
    }

    if (ngx_http_oidc_verify_signature(pr, &body, &ctx->id_token, &jwt)
        != NGX_OK)
    {
        if (ctx->phase == OIDC_PHASE_REFRESH) {
            ngx_http_oidc_refresh_failed(pr, ctx, mcf);

        } else if (ctx->phase == OIDC_PHASE_BACKCHANNEL) {
            ngx_http_oidc_finish(pr, NGX_HTTP_BAD_REQUEST);

        } else {
            ngx_http_oidc_finish(pr, NGX_HTTP_UNAUTHORIZED);
        }
        return NGX_OK;
    }

    grants = jwt_get_grants_json(jwt, NULL);
    jwt_free(jwt);

    if (grants == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: cannot read the ID token payload");
        ngx_http_oidc_finish(pr, NGX_HTTP_UNAUTHORIZED);
        return NGX_OK;
    }

    payload = json_loads(grants, 0, &jerr);
    jwt_free_str(grants);

    if (payload == NULL || !json_is_object(payload)) {
        if (payload) {
            json_decref(payload);
        }
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: ID token payload is not a JSON object");
        ngx_http_oidc_finish(pr, NGX_HTTP_UNAUTHORIZED);
        return NGX_OK;
    }

    if (ctx->phase == OIDC_PHASE_BACKCHANNEL) {
        ngx_int_t  purge;

        if (ngx_http_oidc_validate_logout_token(pr, lcf, ctx, payload)
            != NGX_OK)
        {
            json_decref(payload);
            ngx_http_oidc_finish(pr, NGX_HTTP_BAD_REQUEST);
            return NGX_OK;
        }

        json_decref(payload);

        purge = ngx_http_oidc_purge_sessions(pr, ctx, mcf);

        if (purge == NGX_AGAIN) {
            return NGX_OK;            /* the Redis handler resumes */
        }

        if (purge != NGX_OK) {
            ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_OK;
        }

        ctx->waiting = 0;
        pr->write_event_handler = ngx_http_core_run_phases;

        return NGX_OK;
    }

    if (ngx_http_oidc_validate_claims(pr, lcf, ctx, payload) != NGX_OK) {
        json_decref(payload);

        if (ctx->phase == OIDC_PHASE_REFRESH) {
            ngx_http_oidc_refresh_failed(pr, ctx, mcf);

        } else if (ctx->phase == OIDC_PHASE_BACKCHANNEL) {
            ngx_http_oidc_finish(pr, NGX_HTTP_BAD_REQUEST);

        } else {
            ngx_http_oidc_finish(pr, NGX_HTTP_UNAUTHORIZED);
        }
        return NGX_OK;
    }

    ngx_http_oidc_merge_claims(pr, ctx, lcf, payload);
    json_decref(payload);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "OIDC: ID token verified");

    if (ctx->phase == OIDC_PHASE_REFRESH) {
        ngx_int_t  renew = ngx_http_oidc_renew_session(pr, ctx, mcf, lcf);

        if (renew == NGX_AGAIN) {
            return NGX_OK;            /* the Redis handler resumes the request */
        }

        if (renew != NGX_OK) {
            ngx_http_oidc_refresh_failed(pr, ctx, mcf);
            return NGX_OK;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "OIDC: tokens refreshed");

        ctx->refreshed = 1;
        ctx->waiting   = 0;
        pr->write_event_handler = ngx_http_core_run_phases;

        return NGX_OK;
    }

    if (lcf->oidc_use_userinfo
        && ctx->access_token.len > 0
        && ctx->metadata->userinfo_endpoint.len > 0)
    {
        if (ngx_http_oidc_start_userinfo_request(pr) == NGX_OK) {
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: cannot start the UserInfo request, "
                      "continuing with ID token claims only");
    }

    ngx_http_oidc_issue_session_and_redirect(pr, ctx, mcf);

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  UserInfo
 * ------------------------------------------------------------------------ */

static ngx_int_t
ngx_http_oidc_start_userinfo_request(ngx_http_request_t *r)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_http_oidc_ctx_t         *ctx;
    ngx_str_t                    uri = ngx_string("/_oidc_userinfo");
    size_t                       len;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL || ctx->access_token.len == 0) {
        return NGX_ERROR;
    }

    /*
     * The access token is published as a ready-made Authorization header so
     * that it never travels as a subrequest argument (which would end up in
     * the upstream request line and therefore in logs).
     */
    len = sizeof("Bearer ") - 1 + ctx->access_token.len;
    ctx->userinfo_bearer.data = ngx_pnalloc(r->pool, len);
    if (ctx->userinfo_bearer.data == NULL) {
        return NGX_ERROR;
    }

    ctx->userinfo_bearer.len =
        ngx_snprintf(ctx->userinfo_bearer.data, len, "Bearer %V",
                     &ctx->access_token) - ctx->userinfo_bearer.data;

    ctx->userinfo_url = ctx->metadata->userinfo_endpoint;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_ERROR;
    }

    psr->handler = ngx_http_oidc_userinfo_handler;
    psr->data    = NULL;

    ctx->userinfo_attempted = 1;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_ERROR;
    }

    ctx->waiting = 1;

    return NGX_OK;
}


/*
 * UserInfo completion handler.
 *
 * A failing UserInfo call is not fatal: the ID token claims are already
 * verified, so the session is issued with whatever we have.
 */
static ngx_int_t
ngx_http_oidc_userinfo_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t        *pr = r->parent;
    ngx_http_oidc_ctx_t       *ctx;
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_http_oidc_main_conf_t *mcf;
    ngx_str_t                  body;
    json_t                    *root;
    json_error_t               jerr;
    const char                *sub;
    json_t                    *v;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL || mcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->userinfo_handled || ctx->done) {
        return rc;
    }
    ctx->userinfo_handled = 1;

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: UserInfo request failed, status: %ui",
                      r->headers_out.status);
        goto issue;
    }

    if (ngx_http_oidc_subrequest_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: UserInfo response has no body");
        goto issue;
    }

    root = json_loadb((const char *) body.data, body.len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: UserInfo JSON parse error: %s", jerr.text);
        if (root) {
            json_decref(root);
        }
        goto issue;
    }

    /*
     * OIDC Core 5.3.2: the UserInfo sub MUST match the ID token sub.
     */
    v   = json_object_get(root, "sub");
    sub = json_is_string(v) ? json_string_value(v) : NULL;

    if (sub == NULL
        || ctx->claims.sub.len == 0
        || ngx_strlen(sub) != ctx->claims.sub.len
        || ngx_strncmp(sub, ctx->claims.sub.data, ctx->claims.sub.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: UserInfo sub does not match the ID token sub, "
                      "response ignored");
        json_decref(root);
        goto issue;
    }

    ngx_http_oidc_merge_claims(pr, ctx, lcf, root);
    json_decref(root);

issue:

    ngx_http_oidc_issue_session_and_redirect(pr, ctx, mcf);

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  Session cookie
 * ------------------------------------------------------------------------ */

/*
 * Session cookie layout:
 *
 *   oidc_auth = HMAC_HEX(64) || PAYLOAD
 *   PAYLOAD   = B64(sub):B64(email):B64(name):issued_at
 *               [ |B64(key):B64(value) ]...
 *
 * Every field is Base64 encoded so that ':' inside a value cannot confuse the
 * parser.  The payload is capped at OIDC_SESSION_MAX_PAYLOAD bytes to stay
 * within the browser's 4096 byte cookie limit.
 */
/*
 * Generate a 256 bit session id for the server side stores.
 */
static ngx_int_t
ngx_http_oidc_new_sid(ngx_http_request_t *r, ngx_str_t *sid)
{
    sid->data = ngx_pnalloc(r->pool, 64);
    if (sid->data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_oidc_random_hex(sid->data, 32) != NGX_OK) {
        return NGX_ERROR;
    }

    sid->len = 64;

    return NGX_OK;
}


/*
 * How long a session may live.  oidc_session_timeout 0 disables the check, but
 * a server side store still needs an upper bound to reclaim entries.
 */
static time_t
ngx_http_oidc_session_lifetime(ngx_http_oidc_loc_conf_t *lcf)
{
    return lcf->session_timeout > 0 ? lcf->session_timeout : 12 * 60 * 60;
}


/*
 * Persist the session and build the value of the oidc_auth cookie.
 *
 * Without a store the cookie carries the claims themselves, authenticated
 * with HMAC-SHA256:
 *
 *   oidc_auth = HMAC_HEX(64) || B64(sub):B64(email):B64(name):issued[|...]
 *
 * With a store the cookie carries only the session id and the claims and
 * tokens stay in shared memory or in Redis.
 *
 * Returns NGX_OK when the session is saved, NGX_AGAIN when a Redis call is in
 * flight (the completion handler continues with `after`), NGX_ERROR on
 * failure.  The cookie value is left in ctx->pending_cookie.
 */
static ngx_int_t
ngx_http_oidc_save_session(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf, ngx_http_oidc_loc_conf_t *lcf,
    time_t issued, ngx_uint_t after)
{
    ngx_str_t     claims, record;
    time_t        ttl = ngx_http_oidc_session_lifetime(lcf);
    u_char       *p;
    u_char        mac[32], mac_hex[64];
    unsigned int  mac_len;

    if (ngx_http_oidc_build_claims(r, ctx, issued, &claims) != NGX_OK) {
        return NGX_ERROR;
    }

    ctx->session_issued = issued;

    if (mcf->store != OIDC_STORE_COOKIE) {

        if (ctx->sid.len == 0
            && ngx_http_oidc_new_sid(r, &ctx->sid) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_http_oidc_build_record(r, ctx, &claims, issued, &record)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        ctx->pending_cookie = ctx->sid;

        if (mcf->store == OIDC_STORE_REDIS) {
            return ngx_http_oidc_redis_save(r, ctx, &record, ttl, after)
                   == NGX_AGAIN ? NGX_AGAIN : NGX_ERROR;
        }

        return ngx_http_oidc_sess_store(r, mcf->shm_zone, &ctx->sid, &record,
                                        &ctx->claims.sub, &ctx->oidc_sid,
                                        issued + ttl);
    }

    if (!mcf->secret_initialized) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the session cookie secret is not initialised");
        return NGX_ERROR;
    }

    HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
         claims.data, claims.len, mac, &mac_len);
    ngx_hex_dump(mac_hex, mac, sizeof(mac));

    ctx->pending_cookie.len  = sizeof(mac_hex) + claims.len;
    ctx->pending_cookie.data = ngx_pnalloc(r->pool, ctx->pending_cookie.len);
    if (ctx->pending_cookie.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(ctx->pending_cookie.data, mac_hex, sizeof(mac_hex));
    ngx_memcpy(p, claims.data, claims.len);

    return NGX_OK;
}


/*
 * Work out where to send the browser after a successful login.  Only local
 * paths are accepted: "//host" and "/\host" are absolute references to another
 * origin and would turn the callback into an open redirect.
 */
static void
ngx_http_oidc_set_return_to(ngx_http_request_t *r, ngx_table_elt_t *location)
{
    ngx_str_t  return_to = ngx_null_string;
    ngx_str_t  decoded;
    u_char    *src, *dst;
    size_t     i;

    ngx_str_set(&location->value, "/");

    (void) ngx_http_oidc_get_cookie(r, "oidc_return_to",
                                    sizeof("oidc_return_to") - 1, &return_to);

    if (return_to.len == 0 || return_to.len > OIDC_RETURN_TO_MAX) {
        return;
    }

    decoded.data = ngx_pnalloc(r->pool, return_to.len + 1);
    if (decoded.data == NULL) {
        return;
    }

    src = return_to.data;
    dst = decoded.data;
    ngx_unescape_uri(&dst, &src, return_to.len, 0);
    decoded.len = dst - decoded.data;
    decoded.data[decoded.len] = '\0';

    if (decoded.len == 0
        || decoded.data[0] != '/'
        || (decoded.len > 1
            && (decoded.data[1] == '/' || decoded.data[1] == '\\')))
    {
        return;
    }

    for (i = 0; i < decoded.len; i++) {
        if (decoded.data[i] < 0x20 || decoded.data[i] > 0x7e) {
            return;
        }
    }

    location->value = decoded;
}


static void
ngx_http_oidc_clear_transaction_cookies(ngx_http_request_t *r)
{
    (void) ngx_http_oidc_clear_cookie(r, "oidc_state" OIDC_COOKIE_EXPIRED);
    (void) ngx_http_oidc_clear_cookie(r, "oidc_nonce" OIDC_COOKIE_EXPIRED);
    (void) ngx_http_oidc_clear_cookie(r, "oidc_return_to" OIDC_COOKIE_EXPIRED);
    (void) ngx_http_oidc_clear_cookie(r,
                                      "oidc_pkce_verifier" OIDC_COOKIE_EXPIRED);
}


/*
 * Hand the session cookie to the browser and redirect back to the URI the
 * login started from.
 */
static void
ngx_http_oidc_complete_login(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx)
{
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_table_elt_t           *location;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    if (ngx_http_oidc_add_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                 &ctx->pending_cookie,
                                 ngx_http_oidc_session_lifetime(lcf)) != NGX_OK)
    {
        ngx_http_oidc_finish(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_oidc_clear_transaction_cookies(r);

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        ngx_http_oidc_finish(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");
    ngx_http_oidc_set_return_to(r, location);

    r->headers_out.status   = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.location = location;

    ngx_http_oidc_finish(r, NGX_HTTP_MOVED_TEMPORARILY);
}


static void
ngx_http_oidc_issue_session_and_redirect(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf)
{
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_int_t                  rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    rc = ngx_http_oidc_save_session(r, ctx, mcf, lcf, ngx_time(),
                                    OIDC_AFTER_LOGIN);

    if (rc == NGX_AGAIN) {
        return;                       /* the Redis handler finishes the login */
    }

    if (rc != NGX_OK) {
        ngx_http_oidc_finish(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_oidc_complete_login(r, ctx);
}


/*
 * Restore the claims of a session that has just been read from a store, and
 * check that it has not outlived oidc_session_timeout.
 */
static ngx_int_t
ngx_http_oidc_accept_session(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx,
    ngx_str_t *claims, time_t issued)
{
    time_t  now = ngx_time();

    if (ngx_http_oidc_parse_claims(r, ctx, claims, &issued) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (issued > now + OIDC_CLOCK_SKEW) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "OIDC: the session was issued in the future");
        return NGX_DECLINED;
    }

    if (lcf->session_timeout > 0 && now - issued > lcf->session_timeout) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "OIDC: session expired, re-authenticating");
        return NGX_DECLINED;
    }

    ctx->session_issued = issued;

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_finish_record_load(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, ngx_str_t *record)
{
    ngx_str_t  claims;
    time_t     issued;

    if (ngx_http_oidc_parse_record(r, ctx, record, &claims, &issued) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: malformed session record");
        return NGX_DECLINED;
    }

    return ngx_http_oidc_accept_session(r, lcf, ctx, &claims, issued);
}


/*
 * Load and validate the session the oidc_auth cookie points at.
 *
 * Returns NGX_OK when the session is valid, NGX_DECLINED when there is none,
 * NGX_AGAIN when a Redis lookup is in flight and NGX_ERROR on failure.
 */
static ngx_int_t
ngx_http_oidc_load_session(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t     cookie = ngx_null_string;
    ngx_str_t     claims, record;
    time_t        issued;
    u_char        mac[32], mac_hex[64];
    unsigned int  mac_len;
    ngx_int_t     rc;

    if (ctx->session_loaded) {
        return ctx->session_valid ? NGX_OK : NGX_DECLINED;
    }

    if (ngx_http_oidc_get_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                 &cookie) != NGX_OK)
    {
        ctx->session_loaded = 1;
        return NGX_DECLINED;
    }

    /* This runs again after a refresh, so start from a clean slate. */
    ngx_memzero(&ctx->claims, sizeof(ngx_http_oidc_claims_t));
    ctx->extra_claims = NULL;

    if (mcf->store == OIDC_STORE_REDIS) {

        if (cookie.len != 64) {
            ctx->session_loaded = 1;
            return NGX_DECLINED;
        }

        if (ngx_http_oidc_str_copy(r->pool, &ctx->sid, (char *) cookie.data,
                                   cookie.len) != NGX_OK)
        {
            return NGX_ERROR;
        }

        return ngx_http_oidc_redis_load(r, ctx) == NGX_AGAIN
               ? NGX_AGAIN : NGX_ERROR;
    }

    ctx->session_loaded = 1;

    if (mcf->store == OIDC_STORE_SHM) {

        if (cookie.len != 64) {
            return NGX_DECLINED;
        }

        ctx->sid = cookie;

        if (ngx_http_oidc_sess_load(r, mcf->shm_zone, &cookie, &record)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }

        rc = ngx_http_oidc_finish_record_load(r, lcf, ctx, &record);
        ctx->session_valid = (rc == NGX_OK);

        return rc;
    }

    if (!mcf->secret_initialized || cookie.len <= sizeof(mac_hex)) {
        return NGX_DECLINED;
    }

    claims.data = cookie.data + sizeof(mac_hex);
    claims.len  = cookie.len - sizeof(mac_hex);

    HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
         claims.data, claims.len, mac, &mac_len);
    ngx_hex_dump(mac_hex, mac, sizeof(mac));

    if (CRYPTO_memcmp(cookie.data, mac_hex, sizeof(mac_hex)) != 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "OIDC: session cookie signature mismatch");
        return NGX_DECLINED;
    }

    issued = 0;
    rc = ngx_http_oidc_accept_session(r, lcf, ctx, &claims, issued);
    ctx->session_valid = (rc == NGX_OK);

    return rc;
}


/*
 * Completion handler of every Redis call.
 */
static ngx_int_t
ngx_http_oidc_redis_done(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t         *pr = r->parent;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_http_oidc_loc_conf_t   *lcf;
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_http_oidc_redis_ctx_t  *rctx;
    ngx_uint_t                  ok, after;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL || mcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->redis_handled || ctx->done) {
        return rc;
    }
    ctx->redis_handled = 1;

    rctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    ok   = (rc != NGX_ERROR && r->headers_out.status == NGX_HTTP_OK);
    after = ctx->redis_after;

    if (!ok && r->headers_out.status != NGX_HTTP_NOT_FOUND) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the redis request failed, status: %ui",
                      r->headers_out.status);
    }

    switch (ctx->redis_op) {

    case OIDC_REDIS_LOAD:

        ctx->session_loaded = 1;
        ctx->session_valid  = 0;

        if (ok && rctx != NULL && rctx->value.len) {
            ctx->session_valid = (ngx_http_oidc_finish_record_load(pr, lcf, ctx,
                                      &rctx->value) == NGX_OK);
        }

        break;

    case OIDC_REDIS_PURGE:
        ctx->purged = 1;
        break;

    case OIDC_REDIS_SAVE:

        if (!ok) {
            if (after == OIDC_AFTER_LOGIN) {
                ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_OK;
            }

            /* A failed renewal simply drops the session. */
            ngx_http_oidc_refresh_failed(pr, ctx, mcf);
            return NGX_OK;
        }

        break;

    default:
        break;
    }

    switch (after) {

    case OIDC_AFTER_LOGIN:
        ngx_http_oidc_complete_login(pr, ctx);
        return NGX_OK;

    case OIDC_AFTER_LOGOUT:
        ngx_http_oidc_finish(pr, NGX_HTTP_MOVED_TEMPORARILY);
        return NGX_OK;

    case OIDC_AFTER_REFRESH:
        (void) ngx_http_oidc_add_cookie(pr, "oidc_auth",
                                        sizeof("oidc_auth") - 1,
                                        &ctx->pending_cookie,
                                        ngx_http_oidc_session_lifetime(lcf));
        ctx->refreshed = 1;
        break;

    default:
        break;
    }

    ctx->waiting = 0;
    pr->write_event_handler = ngx_http_core_run_phases;

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  Token introspection (RFC 7662)
 * ------------------------------------------------------------------------ */

static ngx_int_t ngx_http_oidc_introspect_handler(ngx_http_request_t *r,
    void *data, ngx_int_t rc);


static ngx_int_t
ngx_http_oidc_start_introspect_request(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_http_request_t          *sr;
    ngx_http_post_subrequest_t  *psr;
    ngx_str_t                    uri = ngx_string("/_oidc_introspect");
    size_t                       len;
    u_char                      *p;

    if (ngx_http_oidc_client_auth_prepare(r, lcf, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("token=") - 1 + ngx_http_oidc_escaped_len(&ctx->access_token)
        + sizeof("&token_type_hint=access_token") - 1
        + sizeof("&client_id=") - 1 + ngx_http_oidc_escaped_len(&lcf->client_id)
        + ngx_http_oidc_client_auth_len(lcf, ctx);

    ctx->introspect_body.data = ngx_pnalloc(r->pool, len);
    if (ctx->introspect_body.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(ctx->introspect_body.data, "token=", sizeof("token=") - 1);
    p = ngx_http_oidc_escape(p, &ctx->access_token);
    p = ngx_cpymem(p, "&token_type_hint=access_token",
                   sizeof("&token_type_hint=access_token") - 1);
    p = ngx_cpymem(p, "&client_id=", sizeof("&client_id=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->client_id);
    p = ngx_http_oidc_client_auth_append(p, lcf, ctx);

    ctx->introspect_body.len = p - ctx->introspect_body.data;
    ctx->introspect_url      = ctx->metadata->introspection_endpoint;
    ctx->token_basic         = (lcf->client_auth == OIDC_CLIENT_AUTH_BASIC)
                               ? lcf->client_basic
                               : (ngx_str_t) ngx_null_string;

    psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
    if (psr == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    psr->handler = ngx_http_oidc_introspect_handler;
    psr->data    = NULL;

    ctx->introspect_attempted = 1;

    if (ngx_http_subrequest(r, &uri, NULL, &sr, psr,
                            NGX_HTTP_SUBREQUEST_IN_MEMORY) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->waiting = 1;

    return NGX_AGAIN;
}


/*
 * Introspection completion handler.
 *
 * "active": false means the token was revoked at the IdP, so the session is
 * dropped and the request falls back to re-authentication.  A failure to
 * reach the introspection endpoint is not treated as a revocation: it is
 * logged and the session is left alone, and the check is retried on the next
 * request because the timestamp is not updated.
 */
static ngx_int_t
ngx_http_oidc_introspect_handler(ngx_http_request_t *r, void *data,
    ngx_int_t rc)
{
    ngx_http_request_t         *pr = r->parent;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_http_oidc_loc_conf_t   *lcf;
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_str_t                   body;
    json_t                     *root, *active;
    json_error_t                jerr;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    lcf = ngx_http_get_module_loc_conf(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || lcf == NULL || mcf == NULL) {
        ngx_http_oidc_finish(pr, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    if (ctx->introspect_handled || ctx->done) {
        return rc;
    }
    ctx->introspect_handled = 1;

    if (rc == NGX_ERROR || r->headers_out.status != NGX_HTTP_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: introspection request failed, status: %ui",
                      r->headers_out.status);
        goto resume;
    }

    if (ngx_http_oidc_subrequest_body(r, &body) != NGX_OK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: introspection response has no body");
        goto resume;
    }

    root = json_loadb((const char *) body.data, body.len, 0, &jerr);
    if (root == NULL || !json_is_object(root)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "OIDC: introspection JSON parse error: %s", jerr.text);
        if (root) {
            json_decref(root);
        }
        goto resume;
    }

    active = json_object_get(root, "active");

    if (json_is_true(active)) {
        json_decref(root);

        ctx->introspected = ngx_time();

        /* Persist the new timestamp without extending the session. */
        if (ngx_http_oidc_save_session(pr, ctx, mcf, lcf, ctx->session_issued,
                                       OIDC_AFTER_RESUME) == NGX_AGAIN)
        {
            return NGX_OK;
        }

        goto resume;
    }

    json_decref(root);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "OIDC: the access token is no longer active, "
                  "dropping the session");

    ctx->session_valid = 0;

    if (ctx->sid.len) {
        if (mcf->store == OIDC_STORE_SHM) {
            ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);

        } else if (mcf->store == OIDC_STORE_REDIS) {
            if (ngx_http_oidc_redis_delete(pr, ctx, OIDC_AFTER_RESUME)
                == NGX_AGAIN)
            {
                return NGX_OK;
            }
        }
    }

resume:

    ctx->waiting = 0;
    pr->write_event_handler = ngx_http_core_run_phases;

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  RP-Initiated Logout
 * ------------------------------------------------------------------------ */

/*
 * Remove the session behind the current cookie.  With Redis this needs a round
 * trip, so the caller gets NGX_AGAIN and the redirect is emitted by the Redis
 * completion handler (the response headers are already in place).
 */
static ngx_int_t
ngx_http_oidc_drop_session(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf)
{
    if (ctx->sid.len == 0) {
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    if (mcf->store == OIDC_STORE_SHM) {
        ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    if (mcf->store == OIDC_STORE_REDIS) {
        return ngx_http_oidc_redis_delete(r, ctx, OIDC_AFTER_LOGOUT);
    }

    return NGX_HTTP_MOVED_TEMPORARILY;
}


/*
 * Drop the session and send the browser to the IdP's end_session_endpoint so
 * that the login session is terminated there as well.  Without such an
 * endpoint the local session is still cleared and the browser is sent to
 * oidc_post_logout_redirect_uri.
 */
static ngx_int_t
ngx_http_oidc_logout(ngx_http_request_t *r, ngx_http_oidc_loc_conf_t *lcf,
    ngx_http_oidc_main_conf_t *mcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_table_elt_t  *location;
    ngx_str_t        *endpoint;
    size_t            len;
    u_char           *p;
    ngx_uint_t        has_query;
    ngx_int_t         rc;

    /* Loading the session gives us the ID token to use as id_token_hint. */
    rc = ngx_http_oidc_load_session(r, lcf, mcf, ctx);
    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return rc == NGX_AGAIN ? NGX_AGAIN : NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_oidc_clear_cookie(r, "oidc_auth" OIDC_COOKIE_EXPIRED)
        != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_http_oidc_clear_transaction_cookies(r);

    location = ngx_list_push(&r->headers_out.headers);
    if (location == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    location->hash = 1;
    ngx_str_set(&location->key, "Location");

    endpoint = &ctx->metadata->end_session_endpoint;

    if (endpoint->len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "OIDC: the provider advertises no end_session_endpoint, "
                      "only the local session was cleared");

        if (lcf->post_logout_redirect_uri.len) {
            location->value = lcf->post_logout_redirect_uri;
        } else {
            ngx_str_set(&location->value, "/");
        }

        r->headers_out.status   = NGX_HTTP_MOVED_TEMPORARILY;
        r->headers_out.location = location;

        return ngx_http_oidc_drop_session(r, ctx, mcf);
    }

    has_query = (ngx_strlchr(endpoint->data, endpoint->data + endpoint->len,
                             '?') != NULL);

    len = endpoint->len + 1
        + sizeof("client_id=") - 1 + ngx_http_oidc_escaped_len(&lcf->client_id)
        + (ctx->id_token.len
           ? sizeof("&id_token_hint=") - 1
             + ngx_http_oidc_escaped_len(&ctx->id_token)
           : 0)
        + (lcf->post_logout_redirect_uri.len
           ? sizeof("&post_logout_redirect_uri=") - 1
             + ngx_http_oidc_escaped_len(&lcf->post_logout_redirect_uri)
           : 0);

    location->value.data = ngx_pnalloc(r->pool, len);
    if (location->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(location->value.data, endpoint->data, endpoint->len);
    *p++ = has_query ? '&' : '?';

    p = ngx_cpymem(p, "client_id=", sizeof("client_id=") - 1);
    p = ngx_http_oidc_escape(p, &lcf->client_id);

    if (ctx->id_token.len) {
        p = ngx_cpymem(p, "&id_token_hint=", sizeof("&id_token_hint=") - 1);
        p = ngx_http_oidc_escape(p, &ctx->id_token);
    }

    if (lcf->post_logout_redirect_uri.len) {
        p = ngx_cpymem(p, "&post_logout_redirect_uri=",
                       sizeof("&post_logout_redirect_uri=") - 1);
        p = ngx_http_oidc_escape(p, &lcf->post_logout_redirect_uri);
    }

    location->value.len = p - location->value.data;

    r->headers_out.status   = NGX_HTTP_MOVED_TEMPORARILY;
    r->headers_out.location = location;

    return ngx_http_oidc_drop_session(r, ctx, mcf);
}


/* ------------------------------------------------------------------------ *
 *  Back-channel and front-channel logout
 *
 *  Both are notifications from the provider rather than browser navigations,
 *  so they identify the session by the "sub" and "sid" claims instead of by
 *  the cookie.  A server side store is therefore required.
 * ------------------------------------------------------------------------ */

/*
 * Header-only 200, which is what both logout endpoints must answer with.
 */
static ngx_int_t
ngx_http_oidc_send_empty_ok(ngx_http_request_t *r)
{
    ngx_table_elt_t  *h;
    ngx_int_t         rc;

    h = ngx_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    ngx_str_set(&h->key, "Cache-Control");
    ngx_str_set(&h->value, "no-store");

    r->headers_out.status           = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only                  = 1;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_OK);

    return NGX_DONE;
}


/*
 * Remove every session of the subject or provider side session named in
 * ctx->claims.sub / ctx->oidc_sid.
 *
 * Returns NGX_OK when the sessions are gone, NGX_AGAIN when Redis is doing it
 * and NGX_DECLINED when there is no store to purge.
 */
static ngx_int_t
ngx_http_oidc_purge_sessions(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf)
{
    ngx_str_t   key;
    ngx_uint_t  n;

    if (mcf->store == OIDC_STORE_SHM) {
        n = ngx_http_oidc_sess_purge(mcf->shm_zone, &ctx->claims.sub,
                                     &ctx->oidc_sid);

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "OIDC: logout notification dropped %ui session(s)", n);

        ctx->purged = 1;

        return NGX_OK;
    }

    if (mcf->store == OIDC_STORE_REDIS) {

        if (ctx->oidc_sid.len) {
            ngx_http_oidc_redis_key(r, "oidc:x:sid:", &ctx->oidc_sid, &key);

        } else {
            ngx_http_oidc_redis_key(r, "oidc:x:sub:", &ctx->claims.sub, &key);
        }

        if (key.len == 0) {
            return NGX_ERROR;
        }

        return ngx_http_oidc_redis_purge(r, ctx, &key, OIDC_AFTER_RESUME);
    }

    return NGX_DECLINED;
}


/*
 * Validate a back-channel logout token (OpenID Connect Back-Channel Logout
 * 1.0 section 2.6).  The signature has already been checked by the caller.
 */
static ngx_int_t
ngx_http_oidc_validate_logout_token(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx, json_t *payload)
{
    json_t      *v, *item;
    ngx_str_t    issuer, provider;
    const char  *str;
    time_t       iat, now = ngx_time();
    size_t       i, n;
    ngx_uint_t   matched;

    /* ---- iss ---- */
    v = json_object_get(payload, "iss");
    if (!json_is_string(v)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token has no iss claim");
        return NGX_DECLINED;
    }

    issuer.data = (u_char *) json_string_value(v);
    issuer.len  = ngx_strlen(issuer.data);
    provider    = ctx->metadata->issuer.len ? ctx->metadata->issuer
                                            : lcf->oidc_provider;
    ngx_http_oidc_trim_slash(&issuer);
    ngx_http_oidc_trim_slash(&provider);

    if (issuer.len != provider.len
        || ngx_strncmp(issuer.data, provider.data, issuer.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token iss \"%V\" is not \"%V\"",
                      &issuer, &provider);
        return NGX_DECLINED;
    }

    /* ---- aud ---- */
    v = json_object_get(payload, "aud");
    matched = 0;

    if (json_is_string(v)) {
        str = json_string_value(v);
        matched = (ngx_strlen(str) == lcf->client_id.len
                   && ngx_strncmp(str, lcf->client_id.data,
                                  lcf->client_id.len) == 0);

    } else if (json_is_array(v)) {
        n = json_array_size(v);
        for (i = 0; i < n; i++) {
            item = json_array_get(v, i);
            if (!json_is_string(item)) {
                continue;
            }
            str = json_string_value(item);
            if (ngx_strlen(str) == lcf->client_id.len
                && ngx_strncmp(str, lcf->client_id.data,
                               lcf->client_id.len) == 0)
            {
                matched = 1;
                break;
            }
        }
    }

    if (!matched) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token aud is not this client");
        return NGX_DECLINED;
    }

    /* ---- iat ---- */
    v = json_object_get(payload, "iat");
    if (!json_is_integer(v)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token has no iat claim");
        return NGX_DECLINED;
    }

    iat = (time_t) json_integer_value(v);
    if (iat > now + OIDC_CLOCK_SKEW
        || now - iat > OIDC_LOGOUT_TOKEN_MAX_AGE)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token iat %T is out of range", iat);
        return NGX_DECLINED;
    }

    /* ---- events ---- */
    v = json_object_get(payload, "events");
    if (!json_is_object(v)
        || json_object_get(v,
               "http://schemas.openid.net/event/backchannel-logout") == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token has no backchannel-logout event");
        return NGX_DECLINED;
    }

    /* ---- nonce must not be there ---- */
    if (json_object_get(payload, "nonce") != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token must not carry a nonce");
        return NGX_DECLINED;
    }

    /* ---- sub and/or sid ---- */
    ngx_str_null(&ctx->claims.sub);
    ngx_str_null(&ctx->oidc_sid);

    v = json_object_get(payload, "sub");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(r->pool, &ctx->claims.sub,
                                      json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    v = json_object_get(payload, "sid");
    if (json_is_string(v)) {
        (void) ngx_http_oidc_str_copy(r->pool, &ctx->oidc_sid,
                                      json_string_value(v),
                                      ngx_strlen(json_string_value(v)));
    }

    if (ctx->claims.sub.len == 0 && ctx->oidc_sid.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token has neither sub nor sid");
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static void
ngx_http_oidc_backchannel_body_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx != NULL) {
        ctx->body_read = 1;
    }

    r->main->count--;

    ngx_http_core_run_phases(r);
}


/*
 * Pull logout_token out of the application/x-www-form-urlencoded body.
 */
static ngx_int_t
ngx_http_oidc_read_logout_token(ngx_http_request_t *r, ngx_str_t *token)
{
    ngx_chain_t  *cl;
    ngx_buf_t    *b;
    ngx_str_t     body;
    u_char       *p, *end, *eq, *amp, *dst, *src;
    size_t        len;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NGX_DECLINED;
    }

    if (r->request_body->temp_file) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the logout token was buffered to disk, "
                      "raise client_body_buffer_size");
        return NGX_DECLINED;
    }

    len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        len += cl->buf->last - cl->buf->pos;
    }

    if (len == 0 || len > 64 * 1024) {
        return NGX_DECLINED;
    }

    body.data = ngx_pnalloc(r->pool, len);
    if (body.data == NULL) {
        return NGX_ERROR;
    }

    p = body.data;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;
        p = ngx_cpymem(p, b->pos, b->last - b->pos);
    }
    body.len = p - body.data;

    p   = body.data;
    end = body.data + body.len;

    while (p < end) {
        amp = ngx_strlchr(p, end, '&');
        if (amp == NULL) {
            amp = end;
        }

        eq = ngx_strlchr(p, amp, '=');

        if (eq != NULL
            && (size_t) (eq - p) == sizeof("logout_token") - 1
            && ngx_strncmp(p, "logout_token", sizeof("logout_token") - 1) == 0)
        {
            token->data = ngx_pnalloc(r->pool, amp - (eq + 1) + 1);
            if (token->data == NULL) {
                return NGX_ERROR;
            }

            src = eq + 1;
            dst = token->data;
            ngx_unescape_uri(&dst, &src, amp - (eq + 1), 0);
            token->len = dst - token->data;
            token->data[token->len] = '\0';

            return token->len ? NGX_OK : NGX_DECLINED;
        }

        p = amp + 1;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_oidc_backchannel_logout(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_ctx_t *ctx)
{
    ngx_int_t  rc;

    if (ctx->purged) {
        return ngx_http_oidc_send_empty_ok(r);
    }

    if (mcf->store == OIDC_STORE_COOKIE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: back-channel logout needs oidc_session_store");
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (!(r->method & NGX_HTTP_POST)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (!ctx->body_read) {
        r->request_body_in_single_buf = 1;

        rc = ngx_http_read_client_request_body(r,
                                       ngx_http_oidc_backchannel_body_handler);

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        return NGX_DONE;
    }

    if (ctx->jwks_started) {
        /* The JWKS handler owns the outcome from here. */
        return NGX_AGAIN;
    }

    rc = ngx_http_oidc_read_logout_token(r, &ctx->id_token);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the request carries no logout_token");
        return NGX_HTTP_BAD_REQUEST;
    }

    ctx->phase        = OIDC_PHASE_BACKCHANNEL;
    ctx->jwks_started = 1;

    if (ngx_http_oidc_start_jwks_request(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_AGAIN;
}


/*
 * Front-channel logout: the provider loads this endpoint in a hidden iframe
 * with iss and sid, so there is no token to verify and, because the cookie is
 * SameSite=Lax, usually no cookie either.  The session is found by sid.
 */
static ngx_int_t
ngx_http_oidc_frontchannel_logout(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t  iss, sid, issuer, provider;
    ngx_int_t  rc;

    if (ctx->purged) {
        return ngx_http_oidc_send_empty_ok(r);
    }

    if (mcf->store == OIDC_STORE_COOKIE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: front-channel logout needs oidc_session_store");
        return NGX_HTTP_NOT_IMPLEMENTED;
    }

    if (ngx_http_arg(r, (u_char *) "iss", sizeof("iss") - 1, &iss) == NGX_OK) {
        u_char  *src = iss.data;
        u_char  *dst;

        issuer.data = ngx_pnalloc(r->pool, iss.len + 1);
        if (issuer.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        dst = issuer.data;
        ngx_unescape_uri(&dst, &src, iss.len, 0);
        issuer.len = dst - issuer.data;

        provider = ctx->metadata->issuer.len ? ctx->metadata->issuer
                                             : lcf->oidc_provider;
        ngx_http_oidc_trim_slash(&issuer);
        ngx_http_oidc_trim_slash(&provider);

        if (issuer.len != provider.len
            || ngx_strncmp(issuer.data, provider.data, issuer.len) != 0)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "OIDC: front-channel logout from an unknown issuer");
            return NGX_HTTP_BAD_REQUEST;
        }
    }

    if (ngx_http_arg(r, (u_char *) "sid", sizeof("sid") - 1, &sid) != NGX_OK
        || sid.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: front-channel logout without a sid");
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_str_null(&ctx->claims.sub);
    ctx->oidc_sid = sid;

    (void) ngx_http_oidc_clear_cookie(r, "oidc_auth" OIDC_COOKIE_EXPIRED);

    rc = ngx_http_oidc_purge_sessions(r, ctx, mcf);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_oidc_send_empty_ok(r);
}


/* ------------------------------------------------------------------------ *
 *  Access phase
 * ------------------------------------------------------------------------ */

static ngx_http_oidc_provider_metadata_t *
ngx_http_oidc_copy_metadata(ngx_pool_t *pool,
    ngx_http_oidc_provider_metadata_t *src)
{
    ngx_http_oidc_provider_metadata_t  *dst;
    ngx_str_t                          *d, *s;
    ngx_uint_t                          i;

    dst = ngx_pcalloc(pool, sizeof(ngx_http_oidc_provider_metadata_t));
    if (dst == NULL) {
        return NULL;
    }

    for (i = 0; i < sizeof(*dst) / sizeof(ngx_str_t); i++) {
        d = (ngx_str_t *) dst + i;
        s = (ngx_str_t *) src + i;

        if (s->len == 0) {
            continue;
        }

        if (ngx_http_oidc_str_copy(pool, d, (char *) s->data, s->len)
            != NGX_OK)
        {
            return NULL;
        }
    }

    return dst;
}


static ngx_int_t
ngx_http_oidc_handle_callback(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t  code, state, error, state_cookie = ngx_null_string;

    if (ctx->token_attempted) {
        /*
         * The chain reported neither success nor failure.  This should not
         * happen; refuse rather than fall through to the protected content.
         */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: callback reached again without a result");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* The IdP reports failures on the redirect URI as ?error=... */
    if (ngx_http_arg(r, (u_char *) "error", sizeof("error") - 1, &error)
        == NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the IdP rejected the authorization request: %V",
                      &error);
        return NGX_HTTP_FORBIDDEN;
    }

    if (ngx_http_arg(r, (u_char *) "code", sizeof("code") - 1, &code)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the callback has no code parameter");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (ngx_http_arg(r, (u_char *) "state", sizeof("state") - 1, &state)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the callback has no state parameter");
        return NGX_HTTP_BAD_REQUEST;
    }

    (void) ngx_http_oidc_get_cookie(r, "oidc_state", sizeof("oidc_state") - 1,
                                    &state_cookie);

    if (state_cookie.len == 0
        || state.len != state_cookie.len
        || CRYPTO_memcmp(state.data, state_cookie.data, state.len) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the callback state does not match the cookie");
        return NGX_HTTP_FORBIDDEN;
    }

    return ngx_http_oidc_start_token_request(r, lcf, ctx, &code);
}


static ngx_int_t
ngx_http_oidc_access_handler(ngx_http_request_t *r)
{
    ngx_http_oidc_loc_conf_t   *lcf;
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_http_oidc_ctx_t        *ctx;
    ngx_http_oidc_cache_t      *cache;
    ngx_int_t                   rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(r, ngx_http_oidc_module);

    if (lcf->auth_oidc != 1) {
        return NGX_DECLINED;
    }

    /* Our own subrequests must never re-enter the flow. */
    if (r != r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_oidc_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_oidc_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_oidc_module);
    }

    /*
     * NGINX re-runs the phases of the parent request every time one of our
     * subrequests is finalised.  Until the chain has produced a result we must
     * keep waiting, otherwise the request would be finalised while the ID
     * token is still being fetched and verified.
     */
    if (ctx->done) {
        return ctx->status;
    }

    if (ctx->waiting) {
        return NGX_AGAIN;
    }

    if (lcf->oidc_provider.len == 0 || lcf->client_id.len == 0
        || lcf->redirect_uri.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: oidc_provider, oidc_client_id and "
                      "oidc_redirect_uri are all required");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* ---- provider metadata ---- */

    if (ctx->metadata == NULL) {
        cache = lcf->cache;

        if (cache->metadata != NULL && cache->expires > ngx_time()) {
            ctx->metadata = ngx_http_oidc_copy_metadata(r->pool,
                                                        cache->metadata);
            if (ctx->metadata == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

        } else {
            if (ctx->discovery_attempted) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                              "OIDC: discovery already failed for this request");
                return NGX_HTTP_BAD_GATEWAY;
            }

            return ngx_http_oidc_start_discovery(r, lcf, ctx);
        }
    }

    /* ---- logout notifications from the provider ---- */

    if (lcf->backchannel_path.len
        && r->uri.len == lcf->backchannel_path.len
        && ngx_strncmp(r->uri.data, lcf->backchannel_path.data,
                       lcf->backchannel_path.len) == 0)
    {
        return ngx_http_oidc_backchannel_logout(r, lcf, mcf, ctx);
    }

    if (lcf->frontchannel_path.len
        && r->uri.len == lcf->frontchannel_path.len
        && ngx_strncmp(r->uri.data, lcf->frontchannel_path.data,
                       lcf->frontchannel_path.len) == 0)
    {
        return ngx_http_oidc_frontchannel_logout(r, lcf, mcf, ctx);
    }

    /* ---- logout ---- */

    if (lcf->logout_path.len
        && r->uri.len == lcf->logout_path.len
        && ngx_strncmp(r->uri.data, lcf->logout_path.data,
                       lcf->logout_path.len) == 0)
    {
        return ngx_http_oidc_logout(r, lcf, mcf, ctx);
    }

    /* ---- callback ---- */

    if (r->uri.len == lcf->callback_path.len
        && ngx_strncmp(r->uri.data, lcf->callback_path.data,
                       lcf->callback_path.len) == 0)
    {
        return ngx_http_oidc_handle_callback(r, lcf, ctx);
    }

    /* ---- existing session ---- */

    rc = ngx_http_oidc_load_session(r, lcf, mcf, ctx);

    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;             /* the store lookup is in flight */
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rc == NGX_OK) {

        /*
         * Refreshing and introspection both need the tokens, which only a
         * server side store keeps beyond the login request.
         */
        if (mcf->store != OIDC_STORE_COOKIE) {

            if (lcf->refresh_token
                && !ctx->refresh_attempted
                && ctx->refresh_token.len > 0
                && ctx->access_expires > 0
                && ctx->access_expires <= ngx_time() + OIDC_CLOCK_SKEW)
            {
                return ngx_http_oidc_start_refresh_request(r, lcf, ctx);
            }

            if (lcf->introspection
                && !ctx->introspect_attempted
                && ctx->access_token.len > 0
                && ctx->metadata->introspection_endpoint.len > 0
                && ngx_time() - ctx->introspected
                   >= lcf->introspection_interval)
            {
                return ngx_http_oidc_start_introspect_request(r, lcf, ctx);
            }
        }

        return NGX_DECLINED;
    }

    return ngx_http_oidc_redirect_to_idp(r, lcf, ctx);
}


/* ------------------------------------------------------------------------ *
 *  Variables
 * ------------------------------------------------------------------------ */

/*
 * $oidc_claim_<name>
 *
 * sub, email and name come from the dedicated session cookie fields; every
 * other name is looked up in the claims captured from the ID token and the
 * UserInfo response, which are persisted in the session cookie as well.
 */
static ngx_int_t
ngx_http_oidc_claim_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t                    *varname = (ngx_str_t *) data;
    ngx_http_oidc_ctx_t          *ctx;
    ngx_http_oidc_claim_entry_t  *entries;
    ngx_str_t                     name;
    ngx_str_t                    *value = NULL;
    ngx_uint_t                    i;

    name.data = varname->data + (sizeof("oidc_claim_") - 1);
    name.len  = varname->len  - (sizeof("oidc_claim_") - 1);

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_oidc_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    if (name.len == 3 && ngx_strncmp(name.data, "sub", 3) == 0) {
        value = &ctx->claims.sub;

    } else if (name.len == 5 && ngx_strncmp(name.data, "email", 5) == 0) {
        value = &ctx->claims.email;

    } else if (name.len == 4 && ngx_strncmp(name.data, "name", 4) == 0) {
        value = &ctx->claims.name;

    } else if (ctx->extra_claims != NULL) {
        entries = ctx->extra_claims->elts;

        for (i = 0; i < ctx->extra_claims->nelts; i++) {
            if (entries[i].key.len == name.len
                && ngx_strncasecmp(entries[i].key.data, name.data, name.len)
                   == 0)
            {
                value = &entries[i].value;
                break;
            }
        }
    }

    if (value == NULL || value->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len          = value->len;
    v->data         = value->data;
    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;

    return NGX_OK;
}


/*
 * Generic handler for the ngx_str_t members of the request context that are
 * published to the internal locations (URLs, request body, credentials).
 */
static ngx_int_t
ngx_http_oidc_ctx_str_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_oidc_ctx_t  *ctx;
    ngx_str_t            *value;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_oidc_module);
    if (ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    value = (ngx_str_t *) ((char *) ctx + data);

    if (value->len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len          = value->len;
    v->data         = value->data;
    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;

    return NGX_OK;
}


/* ------------------------------------------------------------------------ *
 *  Configuration
 * ------------------------------------------------------------------------ */

static void *
ngx_http_oidc_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_oidc_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_cache_t));
    if (conf->cache == NULL) {
        return NULL;
    }

    /* Redis upstream, following the conventions of the memcached module. */
    conf->redis_upstream.local                = NGX_CONF_UNSET_PTR;
    conf->redis_upstream.socket_keepalive     = NGX_CONF_UNSET;
    conf->redis_upstream.next_upstream_tries  = NGX_CONF_UNSET_UINT;
    conf->redis_upstream.connect_timeout      = NGX_CONF_UNSET_MSEC;
    conf->redis_upstream.send_timeout         = NGX_CONF_UNSET_MSEC;
    conf->redis_upstream.read_timeout         = NGX_CONF_UNSET_MSEC;
    conf->redis_upstream.next_upstream_timeout = NGX_CONF_UNSET_MSEC;
    conf->redis_upstream.buffer_size          = NGX_CONF_UNSET_SIZE;
    conf->redis_upstream.pass_request_headers = 0;
    conf->redis_upstream.pass_request_body    = 0;
    conf->redis_upstream.force_ranges         = 0;
    conf->redis_upstream.cyclic_temp_file     = 0;
    conf->redis_upstream.buffering            = 0;
    conf->redis_upstream.ignore_client_abort  = 0;
    conf->redis_upstream.send_lowat           = 0;
    conf->redis_upstream.bufs.num             = 0;
    conf->redis_upstream.busy_buffers_size    = 0;
    conf->redis_upstream.max_temp_file_size   = 0;
    conf->redis_upstream.temp_file_write_size = 0;
    conf->redis_upstream.intercept_errors     = 1;
    conf->redis_upstream.intercept_404        = 1;
    conf->redis_upstream.pass_headers         = NULL;
    conf->redis_database                      = NGX_CONF_UNSET;

    conf->auth_oidc         = NGX_CONF_UNSET;
    conf->oidc_use_userinfo = NGX_CONF_UNSET;
    conf->session_timeout   = NGX_CONF_UNSET;
    conf->session_claims    = NGX_CONF_UNSET_PTR;
    conf->client_auth       = NGX_CONF_UNSET_UINT;
    conf->refresh_token     = NGX_CONF_UNSET;
    conf->introspection     = NGX_CONF_UNSET;
    conf->introspection_interval = NGX_CONF_UNSET;
    conf->auth_args         = NGX_CONF_UNSET_PTR;

    return conf;
}


/*
 * Derive the local path from a configured URI, which may be either a path or
 * an absolute URI.
 */
static void
ngx_http_oidc_uri_path(ngx_str_t *uri, ngx_str_t *path)
{
    u_char  *p, *end, *q;

    *path = *uri;

    if (uri->len == 0) {
        return;
    }

    end = uri->data + uri->len;

    if (uri->len > 7
        && ngx_strncasecmp(uri->data, (u_char *) "http://", 7) == 0)
    {
        p = ngx_strlchr(uri->data + 7, end, '/');

    } else if (uri->len > 8
               && ngx_strncasecmp(uri->data, (u_char *) "https://", 8) == 0)
    {
        p = ngx_strlchr(uri->data + 8, end, '/');

    } else {
        p = uri->data;
    }

    if (p == NULL) {
        ngx_str_set(path, "/");
        return;
    }

    path->data = p;
    path->len  = end - p;

    /* Drop a query string or fragment if the URI carries one. */
    q = ngx_strlchr(path->data, path->data + path->len, '?');
    if (q != NULL) {
        path->len = q - path->data;
    }
}


/*
 * Pre-compute the Authorization header for client_secret_basic
 * (RFC 6749 section 2.3.1: both values are form-urlencoded before encoding).
 */
static ngx_int_t
ngx_http_oidc_set_client_basic(ngx_conf_t *cf, ngx_http_oidc_loc_conf_t *conf)
{
    ngx_str_t  raw, b64;
    u_char    *p;
    size_t     len;

    ngx_str_null(&conf->client_basic);
    ngx_str_null(&conf->client_post);

    if (conf->client_id.len == 0 || conf->client_secret.len == 0) {
        return NGX_OK;
    }

    len = ngx_http_oidc_escaped_len(&conf->client_id) + 1
        + ngx_http_oidc_escaped_len(&conf->client_secret);

    raw.data = ngx_pnalloc(cf->pool, len);
    if (raw.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_http_oidc_escape(raw.data, &conf->client_id);
    *p++ = ':';
    p = ngx_http_oidc_escape(p, &conf->client_secret);
    raw.len = p - raw.data;

    b64.len  = ngx_base64_encoded_length(raw.len);
    b64.data = ngx_pnalloc(cf->pool, sizeof("Basic ") - 1 + b64.len);
    if (b64.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(b64.data, "Basic ", sizeof("Basic ") - 1);
    b64.data = p;
    ngx_encode_base64(&b64, &raw);

    conf->client_basic.data = p - (sizeof("Basic ") - 1);
    conf->client_basic.len  = sizeof("Basic ") - 1 + b64.len;

    /*
     * client_secret_post: the secret goes into the body.  client_id is always
     * part of the body, so only the secret is added here — sending client_id
     * twice would make a strict token endpoint reject the request.
     */
    len = sizeof("&client_secret=") - 1
        + ngx_http_oidc_escaped_len(&conf->client_secret);

    conf->client_post.data = ngx_pnalloc(cf->pool, len);
    if (conf->client_post.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(conf->client_post.data, "&client_secret=",
                   sizeof("&client_secret=") - 1);
    p = ngx_http_oidc_escape(p, &conf->client_secret);

    conf->client_post.len = p - conf->client_post.data;

    return NGX_OK;
}


/*
 * Copy everything a named oidc_provider block defines into a location that
 * refers to it with "auth_oidc <name>", without overriding what the location
 * sets itself.
 */
static ngx_int_t
ngx_http_oidc_apply_provider(ngx_conf_t *cf, ngx_http_oidc_loc_conf_t *conf)
{
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_http_oidc_provider_t   *provider;
    ngx_http_oidc_loc_conf_t   *p = NULL;
    ngx_uint_t                  i;

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_oidc_module);

    if (mcf->providers != NULL) {
        provider = mcf->providers->elts;

        for (i = 0; i < mcf->providers->nelts; i++) {
            if (provider[i].name.len == conf->provider_name.len
                && ngx_strncmp(provider[i].name.data,
                               conf->provider_name.data,
                               conf->provider_name.len) == 0)
            {
                p = provider[i].conf;
                break;
            }
        }
    }

    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown oidc_provider \"%V\" in auth_oidc",
                           &conf->provider_name);
        return NGX_ERROR;
    }

#define OIDC_INHERIT_STR(field)                                               \
    if (conf->field.data == NULL) { conf->field = p->field; }

    OIDC_INHERIT_STR(oidc_provider)
    OIDC_INHERIT_STR(client_id)
    OIDC_INHERIT_STR(client_secret)
    OIDC_INHERIT_STR(redirect_uri)
    OIDC_INHERIT_STR(oidc_scope)
    OIDC_INHERIT_STR(logout_uri)
    OIDC_INHERIT_STR(post_logout_redirect_uri)
    OIDC_INHERIT_STR(backchannel_logout_uri)
    OIDC_INHERIT_STR(frontchannel_logout_uri)
    OIDC_INHERIT_STR(client_jwt_key)
    OIDC_INHERIT_STR(client_jwt_kid)
    OIDC_INHERIT_STR(client_jwt_alg)

#undef OIDC_INHERIT_STR

    if (conf->oidc_use_userinfo == NGX_CONF_UNSET) {
        conf->oidc_use_userinfo = p->oidc_use_userinfo;
    }

    if (conf->session_timeout == NGX_CONF_UNSET) {
        conf->session_timeout = p->session_timeout;
    }

    if (conf->client_auth == NGX_CONF_UNSET_UINT) {
        conf->client_auth = p->client_auth;
    }

    if (conf->refresh_token == NGX_CONF_UNSET) {
        conf->refresh_token = p->refresh_token;
    }

    if (conf->introspection == NGX_CONF_UNSET) {
        conf->introspection = p->introspection;
    }

    if (conf->introspection_interval == NGX_CONF_UNSET) {
        conf->introspection_interval = p->introspection_interval;
    }

    if (conf->session_claims == NGX_CONF_UNSET_PTR) {
        conf->session_claims = p->session_claims;
    }

    if (conf->auth_args == NGX_CONF_UNSET_PTR) {
        conf->auth_args = p->auth_args;
    }

    return NGX_OK;
}


static char *
ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

    if (conf->provider_name.len
        && ngx_http_oidc_apply_provider(cf, conf) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->auth_oidc, prev->auth_oidc, 0);
    ngx_conf_merge_str_value(conf->oidc_provider, prev->oidc_provider, "");
    ngx_conf_merge_str_value(conf->client_id, prev->client_id, "");
    ngx_conf_merge_str_value(conf->client_secret, prev->client_secret, "");
    ngx_conf_merge_str_value(conf->redirect_uri, prev->redirect_uri, "");
    ngx_conf_merge_str_value(conf->oidc_scope, prev->oidc_scope, "openid");
    ngx_conf_merge_value(conf->oidc_use_userinfo, prev->oidc_use_userinfo, 0);
    ngx_conf_merge_sec_value(conf->session_timeout, prev->session_timeout, 3600);
    ngx_conf_merge_ptr_value(conf->session_claims, prev->session_claims, NULL);
    ngx_conf_merge_str_value(conf->logout_uri, prev->logout_uri, "");
    ngx_conf_merge_str_value(conf->backchannel_logout_uri,
                             prev->backchannel_logout_uri, "");
    ngx_conf_merge_str_value(conf->frontchannel_logout_uri,
                             prev->frontchannel_logout_uri, "");
    ngx_conf_merge_str_value(conf->post_logout_redirect_uri,
                             prev->post_logout_redirect_uri, "");
    ngx_conf_merge_uint_value(conf->client_auth, prev->client_auth,
                              OIDC_CLIENT_AUTH_BASIC);
    ngx_conf_merge_str_value(conf->client_jwt_kid, prev->client_jwt_kid, "");

    if (conf->client_jwt_key.len == 0) {
        conf->client_jwt_key = prev->client_jwt_key;
    }

    /*
     * No default here: the algorithm depends on the method chosen by the
     * location, and baking a default in would let a parent's default win over
     * the child's method.
     */
    if (conf->client_jwt_alg.data == NULL) {
        conf->client_jwt_alg = prev->client_jwt_alg;
    }
    ngx_conf_merge_value(conf->refresh_token, prev->refresh_token, 0);
    ngx_conf_merge_value(conf->introspection, prev->introspection, 0);
    ngx_conf_merge_sec_value(conf->introspection_interval,
                             prev->introspection_interval, 60);
    ngx_conf_merge_ptr_value(conf->auth_args, prev->auth_args, NULL);

    ngx_conf_merge_ptr_value(conf->redis_upstream.local,
                             prev->redis_upstream.local, NULL);
    ngx_conf_merge_value(conf->redis_upstream.socket_keepalive,
                         prev->redis_upstream.socket_keepalive, 0);
    ngx_conf_merge_uint_value(conf->redis_upstream.next_upstream_tries,
                              prev->redis_upstream.next_upstream_tries, 0);
    ngx_conf_merge_msec_value(conf->redis_upstream.connect_timeout,
                              prev->redis_upstream.connect_timeout, 5000);
    ngx_conf_merge_msec_value(conf->redis_upstream.send_timeout,
                              prev->redis_upstream.send_timeout, 5000);
    ngx_conf_merge_msec_value(conf->redis_upstream.read_timeout,
                              prev->redis_upstream.read_timeout, 5000);
    ngx_conf_merge_msec_value(conf->redis_upstream.next_upstream_timeout,
                              prev->redis_upstream.next_upstream_timeout, 0);
    ngx_conf_merge_size_value(conf->redis_upstream.buffer_size,
                              prev->redis_upstream.buffer_size, 16384);
    ngx_conf_merge_bitmask_value(conf->redis_upstream.next_upstream,
                              prev->redis_upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->redis_upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->redis_upstream.next_upstream = NGX_CONF_BITMASK_SET
                                             |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->redis_upstream.upstream == NULL) {
        conf->redis_upstream.upstream = prev->redis_upstream.upstream;
    }

    ngx_conf_merge_str_value(conf->redis_password, prev->redis_password, "");
    ngx_conf_merge_value(conf->redis_database, prev->redis_database, 0);

    ngx_http_oidc_uri_path(&conf->redirect_uri, &conf->callback_path);
    ngx_http_oidc_uri_path(&conf->logout_uri, &conf->logout_path);
    ngx_http_oidc_uri_path(&conf->backchannel_logout_uri,
                           &conf->backchannel_path);
    ngx_http_oidc_uri_path(&conf->frontchannel_logout_uri,
                           &conf->frontchannel_path);

    if (ngx_http_oidc_set_client_basic(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->auth_oidc == 1
        && conf->client_secret.len == 0
        && conf->client_auth != OIDC_CLIENT_AUTH_PRIVATE_JWT)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "auth_oidc is on but oidc_client_secret is not set");
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_oidc_create_main_conf(ngx_conf_t *cf)
{
    return ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_main_conf_t));
}


static char *
ngx_http_oidc_claims_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t  *lcf = conf;
    ngx_str_t                 *value, *name;
    ngx_uint_t                 i;

    if (lcf->session_claims != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    lcf->session_claims = ngx_array_create(cf->pool, cf->args->nelts - 1,
                                           sizeof(ngx_str_t));
    if (lcf->session_claims == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        name = ngx_array_push(lcf->session_claims);
        if (name == NULL) {
            return NGX_CONF_ERROR;
        }
        *name = value[i];
    }

    return NGX_CONF_OK;
}


static ngx_conf_enum_t  ngx_http_oidc_client_auth[] = {
    { ngx_string("basic"),            OIDC_CLIENT_AUTH_BASIC },
    { ngx_string("post"),             OIDC_CLIENT_AUTH_POST },
    { ngx_string("client_secret_jwt"), OIDC_CLIENT_AUTH_SECRET_JWT },
    { ngx_string("private_key_jwt"),  OIDC_CLIENT_AUTH_PRIVATE_JWT },
    { ngx_null_string, 0 }
};


/*
 * oidc_client_jwt_key <file>
 *
 * Loads the PEM private key used to sign the client assertion of
 * private_key_jwt.
 */
static char *
ngx_http_oidc_client_jwt_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t  *lcf = conf;
    ngx_str_t                 *value = cf->args->elts;
    ngx_str_t                  name = value[1];
    ngx_file_t                 file;
    ngx_file_info_t            fi;
    ssize_t                    n;
    size_t                     size;

    if (lcf->client_jwt_key.len) {
        return "is duplicate";
    }

    if (ngx_conf_full_name(cf->cycle, &name, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = name;
    file.log  = cf->log;

    file.fd = ngx_open_file(name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%V\" failed", &name);
        return NGX_CONF_ERROR;
    }

    if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_fd_info_n " \"%V\" failed", &name);
        goto failed;
    }

    size = (size_t) ngx_file_size(&fi);
    if (size == 0 || size > 64 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" is not a usable key file", &name);
        goto failed;
    }

    lcf->client_jwt_key.data = ngx_pnalloc(cf->pool, size + 1);
    if (lcf->client_jwt_key.data == NULL) {
        goto failed;
    }

    n = ngx_read_file(&file, lcf->client_jwt_key.data, size, 0);
    if (n != (ssize_t) size) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_read_file_n " \"%V\" failed", &name);
        goto failed;
    }

    lcf->client_jwt_key.data[size] = '\0';
    lcf->client_jwt_key.len = size;

    ngx_close_file(file.fd);

    return NGX_CONF_OK;

failed:

    ngx_close_file(file.fd);

    return NGX_CONF_ERROR;
}


/*
 * oidc_session_store <size> | redis
 *
 * Chooses where sessions live.  A size creates a shared memory zone; "redis"
 * sends them to the Redis server configured with oidc_redis_pass.  Without
 * this directive the claims travel in the cookie and the tokens are only
 * available during the login request, so RP-Initiated Logout with
 * id_token_hint, refreshing, introspection and back-channel logout all need a
 * store.
 */
static char *
ngx_http_oidc_session_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_main_conf_t  *mcf = conf;
    ngx_http_oidc_shm_t        *shm;
    ngx_str_t                  *value = cf->args->elts;
    ngx_str_t                   name = ngx_string("oidc_session_store");
    ssize_t                     size;

    if (mcf->store != OIDC_STORE_COOKIE) {
        return "is duplicate";
    }

    if (value[1].len == sizeof("redis") - 1
        && ngx_strncmp(value[1].data, "redis", sizeof("redis") - 1) == 0)
    {
        mcf->store = OIDC_STORE_REDIS;
        return NGX_CONF_OK;
    }

    size = ngx_parse_size(&value[1]);

    if (size == NGX_ERROR || size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid oidc_session_store size \"%V\", "
                           "it must be at least %uz bytes",
                           &value[1], 8 * ngx_pagesize);
        return NGX_CONF_ERROR;
    }

    shm = ngx_pcalloc(cf->pool, sizeof(ngx_http_oidc_shm_t));
    if (shm == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone = ngx_shared_memory_add(cf, &name, size,
                                          &ngx_http_oidc_module);
    if (mcf->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    mcf->shm_zone->init = ngx_http_oidc_init_zone;
    mcf->shm_zone->data = shm;
    mcf->shm_size = size;
    mcf->store    = OIDC_STORE_SHM;

    return NGX_CONF_OK;
}


/*
 * oidc_redis_pass <host:port|upstream>
 *
 * Marks the enclosing internal location as the Redis endpoint of the module.
 */
static char *
ngx_http_oidc_redis_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t  *lcf = conf;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_str_t                 *value = cf->args->elts;
    ngx_url_t                  u;

    if (lcf->redis_upstream.upstream) {
        return "is duplicate";
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url        = value[1];
    u.no_resolve = 1;

    lcf->redis_upstream.upstream = ngx_http_upstream_add(cf, &u, 0);
    if (lcf->redis_upstream.upstream == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_oidc_redis_handler;

    return NGX_CONF_OK;
}


/*
 * oidc_provider <name> { ... }
 *
 * Defines a named provider, the way the NGINX Plus module does, so that a
 * location only needs "auth_oidc <name>;".  At server and location level
 * "oidc_provider <url>;" keeps its original meaning.
 */
static char *
ngx_http_oidc_provider_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_main_conf_t  *mcf = conf;
    ngx_http_oidc_provider_t   *provider;
    ngx_http_oidc_loc_conf_t   *pconf;
    ngx_http_conf_ctx_t        *ctx, *pctx;
    ngx_str_t                  *value = cf->args->elts;
    ngx_str_t                   name;
    ngx_conf_t                  save;
    char                       *rv;
    ngx_uint_t                  i;

    /*
     * cf->args is reused while the block is parsed, so the name has to be
     * taken now.
     */
    name = value[1];

    /*
     * "oidc_provider https://idp/..." at http level stays a plain default for
     * every location below it.
     */
    if (ngx_strnstr(name.data, "://", name.len) != NULL) {
        ngx_http_oidc_loc_conf_t  *lcf;

        lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_oidc_module);
        if (lcf->oidc_provider.data != NULL) {
            return "is duplicate";
        }

        lcf->oidc_provider = name;

        return NGX_CONF_OK;
    }

    if (mcf->providers == NULL) {
        mcf->providers = ngx_array_create(cf->pool, 4,
                                          sizeof(ngx_http_oidc_provider_t));
        if (mcf->providers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    provider = mcf->providers->elts;
    for (i = 0; i < mcf->providers->nelts; i++) {
        if (provider[i].name.len == name.len
            && ngx_strncmp(provider[i].name.data, name.data, name.len) == 0)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate oidc_provider \"%V\"", &name);
            return NGX_CONF_ERROR;
        }
    }

    pconf = ngx_http_oidc_create_loc_conf(cf);
    if (pconf == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf  = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->loc_conf[ngx_http_oidc_module.ctx_index] = pconf;

    save = *cf;
    cf->ctx      = ctx;
    cf->cmd_type = NGX_HTTP_OIDC_PROVIDER_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    provider = ngx_array_push(mcf->providers);
    if (provider == NULL) {
        return NGX_CONF_ERROR;
    }

    provider->name = name;
    provider->conf = pconf;

    return NGX_CONF_OK;
}


/*
 * auth_oidc on|off|<provider name>
 */
static char *
ngx_http_oidc_auth_oidc(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_loc_conf_t  *lcf = conf;
    ngx_str_t                 *value = cf->args->elts;

    if (lcf->auth_oidc != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    if (value[1].len == 2 && ngx_strncasecmp(value[1].data,
                                             (u_char *) "on", 2) == 0)
    {
        lcf->auth_oidc = 1;
        return NGX_CONF_OK;
    }

    if (value[1].len == 3 && ngx_strncasecmp(value[1].data,
                                             (u_char *) "off", 3) == 0)
    {
        lcf->auth_oidc = 0;
        return NGX_CONF_OK;
    }

    lcf->auth_oidc     = 1;
    lcf->provider_name = value[1];

    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_oidc_commands[] = {

    /* on | off | <name of an oidc_provider block> */
    { ngx_string("auth_oidc"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_auth_oidc,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* http level: either a named provider block or a plain issuer URL. */
    { ngx_string("oidc_provider"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_oidc_provider_block,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oidc_provider"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_provider),
      NULL },

    /* ---- short names accepted inside an oidc_provider block ---- */

    { ngx_string("issuer"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_provider),
      NULL },

    { ngx_string("client_id"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_id),
      NULL },

    { ngx_string("client_secret"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_secret),
      NULL },

    { ngx_string("redirect_uri"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redirect_uri),
      NULL },

    { ngx_string("scope"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_scope),
      NULL },

    { ngx_string("userinfo"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_use_userinfo),
      NULL },

    { ngx_string("session_timeout"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, session_timeout),
      NULL },

    { ngx_string("logout_uri"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, logout_uri),
      NULL },

    { ngx_string("post_logout_redirect_uri"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, post_logout_redirect_uri),
      NULL },

    { ngx_string("client_auth"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_auth),
      &ngx_http_oidc_client_auth },

    { ngx_string("auth_request_args"),
      NGX_HTTP_OIDC_PROVIDER_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, auth_args),
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

    /* Space separated OAuth 2.0 scopes.  Defaults to "openid". */
    { ngx_string("oidc_scope"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_scope),
      NULL },

    /*
     * Call the UserInfo endpoint after the ID token has been verified.
     * Required for IdPs that keep the ID token minimal (Google, Entra ID).
     */
    { ngx_string("oidc_use_userinfo"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, oidc_use_userinfo),
      NULL },

    /*
     * Lifetime of the session cookie.  0 disables the check (not recommended).
     */
    { ngx_string("oidc_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, session_timeout),
      NULL },

    /*
     * Restrict which claims are exported as $oidc_claim_* and stored in the
     * session cookie.  Without it every non-protocol claim is kept.
     */
    { ngx_string("oidc_claims"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_oidc_claims_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * RP-Initiated Logout: requests to this path drop the session and are
     * redirected to the provider's end_session_endpoint.
     */
    { ngx_string("oidc_logout_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, logout_uri),
      NULL },

    /* Endpoint the provider POSTs a logout token to (Back-Channel Logout). */
    { ngx_string("oidc_backchannel_logout_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, backchannel_logout_uri),
      NULL },

    /* Endpoint the provider loads in an iframe (Front-Channel Logout). */
    { ngx_string("oidc_frontchannel_logout_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, frontchannel_logout_uri),
      NULL },

    /* Where the provider should send the browser after the logout. */
    { ngx_string("oidc_post_logout_redirect_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, post_logout_redirect_uri),
      NULL },

    /*
     * client_secret_basic (default), client_secret_post, client_secret_jwt or
     * private_key_jwt.
     */
    { ngx_string("oidc_client_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_auth),
      &ngx_http_oidc_client_auth },

    /* PEM private key signing the client assertion of private_key_jwt. */
    { ngx_string("oidc_client_jwt_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_client_jwt_key,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /* "kid" header of the client assertion. */
    { ngx_string("oidc_client_jwt_kid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_jwt_kid),
      NULL },

    /* Algorithm of the client assertion (RS256 / HS256 / ES256 ...). */
    { ngx_string("oidc_client_jwt_alg"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_jwt_alg),
      NULL },

    /* Renew the tokens with the refresh token.  Needs oidc_session_store. */
    { ngx_string("oidc_refresh_token"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, refresh_token),
      NULL },

    /* Ask the provider whether the access token is still active (RFC 7662). */
    { ngx_string("oidc_introspection"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, introspection),
      NULL },

    /* How often introspection runs for one session. */
    { ngx_string("oidc_introspection_interval"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, introspection_interval),
      NULL },

    /* Extra parameters appended to the authorization request. */
    { ngx_string("oidc_auth_request_args"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, auth_args),
      NULL },

    /* Redis endpoint used when oidc_session_store is "redis". */
    { ngx_string("oidc_redis_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_redis_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("oidc_redis_password"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_password),
      NULL },

    { ngx_string("oidc_redis_database"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_database),
      NULL },

    { ngx_string("oidc_redis_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_upstream.connect_timeout),
      NULL },

    { ngx_string("oidc_redis_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_upstream.send_timeout),
      NULL },

    { ngx_string("oidc_redis_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_upstream.read_timeout),
      NULL },

    { ngx_string("oidc_redis_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, redis_upstream.buffer_size),
      NULL },

    /* Keep the sessions in a store instead of in the cookie. */
    { ngx_string("oidc_session_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_oidc_session_store,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /*
     * Shared HMAC secret for the session cookie.  Without it every worker
     * generates its own key and cookies do not survive a worker switch.
     */
    { ngx_string("oidc_cookie_secret"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_oidc_main_conf_t, cookie_secret),
      NULL },

      ngx_null_command
};


static ngx_int_t
ngx_http_oidc_init_process(ngx_cycle_t *cycle)
{
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_http_conf_ctx_t        *ctx;

    ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (ctx == NULL) {
        return NGX_OK;
    }

    mcf = ctx->main_conf[ngx_http_oidc_module.ctx_index];
    if (mcf == NULL) {
        return NGX_OK;
    }

    if (mcf->cookie_secret.len > 0) {
        u_char  digest[32];

        /*
         * The configured secret is hashed so that any length is accepted and
         * the raw value never sits in memory as the key itself.
         */
        SHA256(mcf->cookie_secret.data, mcf->cookie_secret.len, digest);
        ngx_memcpy(mcf->hmac_secret, digest, sizeof(mcf->hmac_secret));
        mcf->secret_initialized = 1;

        return NGX_OK;
    }

    if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) != 1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "OIDC: cannot generate a session cookie secret");
        return NGX_ERROR;
    }

    mcf->secret_initialized = 1;

    ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                  "OIDC: oidc_cookie_secret is not set, this worker uses a "
                  "random secret; sessions will break across workers and "
                  "reloads");

    return NGX_OK;
}


static ngx_int_t
ngx_http_oidc_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_http_variable_t        *var;
    ngx_uint_t                  i;

    static struct {
        ngx_str_t  name;
        size_t     offset;
    } ctx_vars[] = {
        { ngx_string("oidc_access_token"),
          offsetof(ngx_http_oidc_ctx_t, access_token) },
        { ngx_string("oidc_discovery_url"),
          offsetof(ngx_http_oidc_ctx_t, discovery_url) },
        { ngx_string("oidc_token_url"),
          offsetof(ngx_http_oidc_ctx_t, token_url) },
        { ngx_string("oidc_jwks_url"),
          offsetof(ngx_http_oidc_ctx_t, jwks_url) },
        { ngx_string("oidc_userinfo_url"),
          offsetof(ngx_http_oidc_ctx_t, userinfo_url) },
        { ngx_string("oidc_token_body"),
          offsetof(ngx_http_oidc_ctx_t, token_body) },
        { ngx_string("oidc_token_basic"),
          offsetof(ngx_http_oidc_ctx_t, token_basic) },
        { ngx_string("oidc_userinfo_bearer"),
          offsetof(ngx_http_oidc_ctx_t, userinfo_bearer) },
        { ngx_string("oidc_id_token"),
          offsetof(ngx_http_oidc_ctx_t, id_token) },
        { ngx_string("oidc_sid"),
          offsetof(ngx_http_oidc_ctx_t, oidc_sid) },
        { ngx_string("oidc_introspect_url"),
          offsetof(ngx_http_oidc_ctx_t, introspect_url) },
        { ngx_string("oidc_introspect_body"),
          offsetof(ngx_http_oidc_ctx_t, introspect_body) },
        { ngx_null_string, 0 }
    };

    ngx_str_t claim_prefix = ngx_string("oidc_claim_");

    var = ngx_http_add_variable(cf, &claim_prefix,
                                NGX_HTTP_VAR_PREFIX|NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_oidc_claim_variable;
    var->data = 0;

    for (i = 0; ctx_vars[i].name.len; i++) {
        var = ngx_http_add_variable(cf, &ctx_vars[i].name,
                                    NGX_HTTP_VAR_NOCACHEABLE);
        if (var == NULL) {
            return NGX_ERROR;
        }
        var->get_handler = ngx_http_oidc_ctx_str_variable;
        var->data = (uintptr_t) ctx_vars[i].offset;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_oidc_access_handler;

    return NGX_OK;
}


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
