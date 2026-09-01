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

    ngx_shm_zone_t  *shm_zone;   /* oidc_session_store: server side sessions */
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
    ngx_str_t    post_logout_redirect_uri;
    ngx_uint_t   client_auth_post;          /* oidc_client_auth post */
    ngx_flag_t   refresh_token;             /* oidc_refresh_token */
    ngx_flag_t   introspection;             /* oidc_introspection */
    time_t       introspection_interval;
    ngx_http_complex_value_t *auth_args;    /* oidc_auth_request_args */

    ngx_str_t    client_basic;        /* "Basic base64(client_id:client_secret)" */
    ngx_str_t    client_post;         /* "&client_secret=..." for client_secret_post */
    ngx_str_t    callback_path;       /* path part of oidc_redirect_uri */
    ngx_str_t    logout_path;         /* path part of oidc_logout_uri */
    ngx_http_oidc_cache_t *cache;     /* per-location discovery cache */
} ngx_http_oidc_loc_conf_t;


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
    ngx_http_oidc_loc_conf_t *lcf, ngx_str_t *cookie);
static time_t ngx_http_oidc_session_lifetime(ngx_http_oidc_loc_conf_t *lcf);


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
 *  Shared memory session store (oidc_session_store)
 *
 *  Keeping the session server side is what makes the ID token, the access
 *  token and the refresh token usable after the login request: they are far
 *  too large, and the refresh token too sensitive, to travel in a cookie.
 *  With the store enabled the cookie carries nothing but a 256 bit random
 *  session id.
 * ------------------------------------------------------------------------ */

typedef struct {
    ngx_rbtree_node_t  node;          /* node.key = crc32 of the session id */
    ngx_queue_t        queue;         /* LRU, most recently used first */
    time_t             expires;
    time_t             issued;
    time_t             access_expires;
    time_t             introspected;
    u_char             sid[64];
    u_short            id_token_len;
    u_short            access_token_len;
    u_short            refresh_token_len;
    u_short            claims_len;
    u_char             data[1];
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
    ngx_str_t *sid, ngx_str_t *claims, ngx_str_t *id_token,
    ngx_str_t *access_token, ngx_str_t *refresh_token,
    time_t issued, time_t expires, time_t access_expires, time_t introspected)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;
    size_t                 size;
    u_char                *p;
    ngx_uint_t             tries;

    if (sid->len != 64
        || id_token->len > OIDC_MAX_TOKEN_LEN
        || access_token->len > OIDC_MAX_TOKEN_LEN
        || refresh_token->len > OIDC_MAX_TOKEN_LEN)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: session data is too large for the store");
        return NGX_ERROR;
    }

    size = offsetof(ngx_http_oidc_sess_t, data)
         + claims->len + id_token->len + access_token->len + refresh_token->len;

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

    sess->node.key      = ngx_crc32_short(sid->data, sid->len);
    sess->expires       = expires;
    sess->issued        = issued;
    sess->access_expires = access_expires;
    sess->introspected  = introspected;
    ngx_memcpy(sess->sid, sid->data, sizeof(sess->sid));

    sess->claims_len        = (u_short) claims->len;
    sess->id_token_len      = (u_short) id_token->len;
    sess->access_token_len  = (u_short) access_token->len;
    sess->refresh_token_len = (u_short) refresh_token->len;

    p = sess->data;
    p = ngx_cpymem(p, claims->data, claims->len);
    p = ngx_cpymem(p, id_token->data, id_token->len);
    p = ngx_cpymem(p, access_token->data, access_token->len);
    ngx_memcpy(p, refresh_token->data, refresh_token->len);

    ngx_rbtree_insert(&shm->sh->rbtree, &sess->node);
    ngx_queue_insert_head(&shm->sh->queue, &sess->queue);

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return NGX_OK;
}


/*
 * Copy a stored session into the request pool.  Returns NGX_DECLINED when the
 * session is unknown or has expired.
 */
static ngx_int_t
ngx_http_oidc_sess_load(ngx_http_request_t *r, ngx_shm_zone_t *zone,
    ngx_str_t *sid, ngx_str_t *claims, ngx_str_t *id_token,
    ngx_str_t *access_token, ngx_str_t *refresh_token,
    time_t *issued, time_t *access_expires, time_t *introspected)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;
    u_char                *buf, *p;
    size_t                 size;
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

    size = sess->claims_len + sess->id_token_len + sess->access_token_len
         + sess->refresh_token_len;

    buf = ngx_pnalloc(r->pool, size ? size : 1);
    if (buf == NULL) {
        rc = NGX_ERROR;
        goto done;
    }

    ngx_memcpy(buf, sess->data, size);

    p = buf;
    claims->data = p;        claims->len        = sess->claims_len;
    p += sess->claims_len;
    id_token->data = p;      id_token->len      = sess->id_token_len;
    p += sess->id_token_len;
    access_token->data = p;  access_token->len  = sess->access_token_len;
    p += sess->access_token_len;
    refresh_token->data = p; refresh_token->len = sess->refresh_token_len;

    *issued         = sess->issued;
    *access_expires = sess->access_expires;
    *introspected   = sess->introspected;

    /* Refresh the LRU position. */
    ngx_queue_remove(&sess->queue);
    ngx_queue_insert_head(&shm->sh->queue, &sess->queue);

    rc = NGX_OK;

done:

    ngx_shmtx_unlock(&shm->shpool->mutex);

    return rc;
}


/*
 * Record the time of the last successful introspection without rewriting the
 * whole session (in particular without extending its lifetime).
 */
static void
ngx_http_oidc_sess_touch(ngx_shm_zone_t *zone, ngx_str_t *sid,
    time_t introspected)
{
    ngx_http_oidc_shm_t   *shm = zone->data;
    ngx_http_oidc_sess_t  *sess;

    ngx_shmtx_lock(&shm->shpool->mutex);

    sess = ngx_http_oidc_sess_lookup(shm->sh, sid);
    if (sess != NULL) {
        sess->introspected = introspected;
    }

    ngx_shmtx_unlock(&shm->shpool->mutex);
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
 * Append the client credentials to a request body when oidc_client_auth is
 * "post"; with "basic" they travel in the Authorization header instead.
 */
static size_t
ngx_http_oidc_client_post_len(ngx_http_oidc_loc_conf_t *lcf)
{
    return lcf->client_auth_post ? lcf->client_post.len : 0;
}


static u_char *
ngx_http_oidc_client_post(u_char *p, ngx_http_oidc_loc_conf_t *lcf)
{
    if (lcf->client_auth_post && lcf->client_post.len) {
        p = ngx_cpymem(p, lcf->client_post.data, lcf->client_post.len);
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

    ctx->token_basic = lcf->client_auth_post ? (ngx_str_t) ngx_null_string
                                             : lcf->client_basic;
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

    if (lcf->client_secret.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: oidc_client_secret is not set");
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
        + ngx_http_oidc_client_post_len(lcf);

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

    p = ngx_http_oidc_client_post(p, lcf);

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

    len = sizeof("grant_type=refresh_token") - 1
        + sizeof("&refresh_token=") - 1
            + ngx_http_oidc_escaped_len(&ctx->refresh_token)
        + sizeof("&client_id=") - 1
            + ngx_http_oidc_escaped_len(&lcf->client_id)
        + ngx_http_oidc_client_post_len(lcf);

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

    p = ngx_http_oidc_client_post(p, lcf);

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
    if (mcf->shm_zone != NULL && ctx->sid.len) {
        ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);
    }

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
    ngx_str_t  cookie;

    if (ngx_http_oidc_save_session(r, ctx, mcf, lcf, &cookie) != NGX_OK) {
        return NGX_ERROR;
    }

    return ngx_http_oidc_add_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                    &cookie,
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
    if (ngx_http_oidc_renew_session(pr, ctx, mcf, lcf) != NGX_OK) {
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

    if (ngx_http_oidc_validate_claims(pr, lcf, ctx, payload) != NGX_OK) {
        json_decref(payload);

        if (ctx->phase == OIDC_PHASE_REFRESH) {
            ngx_http_oidc_refresh_failed(pr, ctx, mcf);
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

        if (ngx_http_oidc_renew_session(pr, ctx, mcf, lcf) != NGX_OK) {
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
 * Generate a 256 bit session id for the shared memory store.
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
 * the shared memory store still needs an upper bound to reclaim entries.
 */
static time_t
ngx_http_oidc_session_lifetime(ngx_http_oidc_loc_conf_t *lcf)
{
    return lcf->session_timeout > 0 ? lcf->session_timeout : 12 * 60 * 60;
}


/*
 * Persist the session and build the value of the oidc_auth cookie.
 *
 * Without oidc_session_store the cookie carries the claims themselves,
 * authenticated with HMAC-SHA256:
 *
 *   oidc_auth = HMAC_HEX(64) || B64(sub):B64(email):B64(name):issued[|...]
 *
 * With the store enabled the cookie carries only the session id and the
 * claims and tokens stay in shared memory.
 */
static ngx_int_t
ngx_http_oidc_save_session(ngx_http_request_t *r, ngx_http_oidc_ctx_t *ctx,
    ngx_http_oidc_main_conf_t *mcf, ngx_http_oidc_loc_conf_t *lcf,
    ngx_str_t *cookie)
{
    ngx_str_t     claims;
    time_t        now = ngx_time();
    u_char       *p;
    u_char        mac[32], mac_hex[64];
    unsigned int  mac_len;

    if (ngx_http_oidc_build_claims(r, ctx, now, &claims) != NGX_OK) {
        return NGX_ERROR;
    }

    if (mcf->shm_zone != NULL) {

        if (ctx->sid.len == 0
            && ngx_http_oidc_new_sid(r, &ctx->sid) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (ngx_http_oidc_sess_store(r, mcf->shm_zone, &ctx->sid, &claims,
                                     &ctx->id_token, &ctx->access_token,
                                     &ctx->refresh_token, now,
                                     now + ngx_http_oidc_session_lifetime(lcf),
                                     ctx->access_expires, ctx->introspected)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        *cookie = ctx->sid;

        return NGX_OK;
    }

    if (!mcf->secret_initialized) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "OIDC: the session cookie secret is not initialised");
        return NGX_ERROR;
    }

    HMAC(EVP_sha256(), mcf->hmac_secret, sizeof(mcf->hmac_secret),
         claims.data, claims.len, mac, &mac_len);
    ngx_hex_dump(mac_hex, mac, sizeof(mac));

    cookie->len  = sizeof(mac_hex) + claims.len;
    cookie->data = ngx_pnalloc(r->pool, cookie->len);
    if (cookie->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(cookie->data, mac_hex, sizeof(mac_hex));
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


static void
ngx_http_oidc_issue_session_and_redirect(ngx_http_request_t *r,
    ngx_http_oidc_ctx_t *ctx, ngx_http_oidc_main_conf_t *mcf)
{
    ngx_http_oidc_loc_conf_t  *lcf;
    ngx_table_elt_t           *location;
    ngx_str_t                  cookie;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_oidc_module);

    if (ngx_http_oidc_save_session(r, ctx, mcf, lcf, &cookie) != NGX_OK) {
        ngx_http_oidc_finish(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_oidc_add_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                 &cookie,
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


/*
 * Validate the oidc_auth cookie and restore everything it refers to.
 *
 * Returns NGX_OK when the session is valid and has not expired.
 */
static ngx_int_t
ngx_http_oidc_verify_session(ngx_http_request_t *r,
    ngx_http_oidc_loc_conf_t *lcf, ngx_http_oidc_main_conf_t *mcf,
    ngx_http_oidc_ctx_t *ctx)
{
    ngx_str_t     cookie = ngx_null_string;
    ngx_str_t     claims;
    time_t        issued, now;
    u_char        mac[32], mac_hex[64];
    unsigned int  mac_len;

    if (ngx_http_oidc_get_cookie(r, "oidc_auth", sizeof("oidc_auth") - 1,
                                 &cookie) != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /* This runs again after a refresh, so start from a clean slate. */
    ngx_memzero(&ctx->claims, sizeof(ngx_http_oidc_claims_t));
    ctx->extra_claims = NULL;

    if (mcf->shm_zone != NULL) {

        if (cookie.len != 64) {
            return NGX_DECLINED;
        }

        if (ngx_http_oidc_sess_load(r, mcf->shm_zone, &cookie, &claims,
                                    &ctx->id_token, &ctx->access_token,
                                    &ctx->refresh_token, &issued,
                                    &ctx->access_expires, &ctx->introspected)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }

        ctx->sid = cookie;

    } else {

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
    }

    if (ngx_http_oidc_parse_claims(r, ctx, &claims, &issued) != NGX_OK) {
        return NGX_DECLINED;
    }

    now = ngx_time();

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

    len = sizeof("token=") - 1 + ngx_http_oidc_escaped_len(&ctx->access_token)
        + sizeof("&token_type_hint=access_token") - 1
        + sizeof("&client_id=") - 1 + ngx_http_oidc_escaped_len(&lcf->client_id)
        + ngx_http_oidc_client_post_len(lcf);

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
    p = ngx_http_oidc_client_post(p, lcf);

    ctx->introspect_body.len = p - ctx->introspect_body.data;
    ctx->introspect_url      = ctx->metadata->introspection_endpoint;
    ctx->token_basic         = lcf->client_auth_post
                               ? (ngx_str_t) ngx_null_string
                               : lcf->client_basic;

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
    ngx_http_oidc_main_conf_t  *mcf;
    ngx_str_t                   body;
    json_t                     *root, *active;
    json_error_t                jerr;

    if (pr == NULL) {
        return NGX_ERROR;
    }

    ctx = ngx_http_get_module_ctx(pr, ngx_http_oidc_module);
    mcf = ngx_http_get_module_main_conf(pr, ngx_http_oidc_module);
    if (ctx == NULL || mcf == NULL) {
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
        ctx->introspected = ngx_time();

        if (mcf->shm_zone != NULL && ctx->sid.len) {
            ngx_http_oidc_sess_touch(mcf->shm_zone, &ctx->sid,
                                     ctx->introspected);
        }

        json_decref(root);
        goto resume;
    }

    json_decref(root);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "OIDC: the access token is no longer active, "
                  "dropping the session");

    if (mcf->shm_zone != NULL && ctx->sid.len) {
        ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);
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

    /* Loading the session gives us the ID token to use as id_token_hint. */
    (void) ngx_http_oidc_verify_session(r, lcf, mcf, ctx);

    if (mcf->shm_zone != NULL && ctx->sid.len) {
        ngx_http_oidc_sess_delete(mcf->shm_zone, &ctx->sid);
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

        return NGX_HTTP_MOVED_TEMPORARILY;
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

    return NGX_HTTP_MOVED_TEMPORARILY;
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

    if (ngx_http_oidc_verify_session(r, lcf, mcf, ctx) == NGX_OK) {

        /*
         * Refreshing and introspection both need the tokens, which only the
         * shared memory store keeps beyond the login request.
         */
        if (mcf->shm_zone != NULL) {

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

    conf->auth_oidc         = NGX_CONF_UNSET;
    conf->oidc_use_userinfo = NGX_CONF_UNSET;
    conf->session_timeout   = NGX_CONF_UNSET;
    conf->session_claims    = NGX_CONF_UNSET_PTR;
    conf->client_auth_post  = NGX_CONF_UNSET_UINT;
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


static char *
ngx_http_oidc_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_oidc_loc_conf_t *prev = parent;
    ngx_http_oidc_loc_conf_t *conf = child;

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
    ngx_conf_merge_str_value(conf->post_logout_redirect_uri,
                             prev->post_logout_redirect_uri, "");
    ngx_conf_merge_uint_value(conf->client_auth_post, prev->client_auth_post, 0);
    ngx_conf_merge_value(conf->refresh_token, prev->refresh_token, 0);
    ngx_conf_merge_value(conf->introspection, prev->introspection, 0);
    ngx_conf_merge_sec_value(conf->introspection_interval,
                             prev->introspection_interval, 60);
    ngx_conf_merge_ptr_value(conf->auth_args, prev->auth_args, NULL);

    ngx_http_oidc_uri_path(&conf->redirect_uri, &conf->callback_path);
    ngx_http_oidc_uri_path(&conf->logout_uri, &conf->logout_path);

    if (ngx_http_oidc_set_client_basic(cf, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->auth_oidc == 1 && conf->client_secret.len == 0) {
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
    { ngx_string("basic"), 0 },   /* client_secret_basic (default) */
    { ngx_string("post"),  1 },   /* client_secret_post */
    { ngx_null_string, 0 }
};


/*
 * oidc_session_store <size>
 *
 * Creates the shared memory zone that keeps sessions server side.  Without it
 * the claims travel in the cookie and the tokens are only available during the
 * login request, so RP-Initiated Logout with id_token_hint, refreshing and
 * introspection all need this directive.
 */
static char *
ngx_http_oidc_session_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_oidc_main_conf_t  *mcf = conf;
    ngx_http_oidc_shm_t        *shm;
    ngx_str_t                  *value = cf->args->elts;
    ngx_str_t                   name = ngx_string("oidc_session_store");
    ssize_t                     size;

    if (mcf->shm_zone != NULL) {
        return "is duplicate";
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

    return NGX_CONF_OK;
}


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

    /* Where the provider should send the browser after the logout. */
    { ngx_string("oidc_post_logout_redirect_uri"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, post_logout_redirect_uri),
      NULL },

    /* client_secret_basic (default) or client_secret_post. */
    { ngx_string("oidc_client_auth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_oidc_loc_conf_t, client_auth_post),
      &ngx_http_oidc_client_auth },

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

    /* Keep the sessions in shared memory instead of in the cookie. */
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
