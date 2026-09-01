# NGINX OIDC モジュール — ソースコードレビュー

## 概要

`ngx_http_oidc_module` は、NGINX Open Source に OpenID Connect (OIDC) 認証機能を追加する C 言語製のダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現することを目的とし、OAuth 2.0 Authorization Code Flow (PKCE) と OpenID Connect Core の ID トークン検証を実装します。

ソースは単一ファイル `ngx_http_oidc_module.c` にまとめられており、以下の外部ライブラリに依存します。

| ライブラリ | 用途 |
|------------|------|
| OpenSSL (libssl / libcrypto) | 乱数生成・HMAC-SHA256・SHA-256・定時間比較 |
| Jansson | JSON パース（Discovery・トークン・JWKS・クレーム） |
| libjwt (>= 1.12) | JWT のデコードと署名検証 |

---

## ファイル構成

```
nginx-oidc/
├── ngx_http_oidc_module.c   # メインソース
├── config                   # NGINX モジュールビルド設定
├── README.md                # 利用者向けドキュメント
├── REVIEW.md                # 本ファイル
├── VERIFICATION.md          # 実機検証レポート
├── TEST_PLAYWRIGHT.md       # E2E テスト手順
└── test/                    # E2E テストスイート
    ├── run-e2e.sh           # ビルド〜実行〜後片付けを行うランナー
    ├── e2e.spec.js          # Playwright E2E テスト
    ├── mock-idp.js          # モック IdP（RS256 / ES256）
    ├── nginx.conf           # テスト用 NGINX 設定
    ├── playwright.config.js # Playwright 設定
    └── package.json         # テスト依存関係
```

---

## データ構造

```c
/* Discovery から取得したエンドポイント情報 */
typedef struct {
    ngx_str_t issuer;                  /* 発行者 URL（iss の検証に使用） */
    ngx_str_t authorization_endpoint;
    ngx_str_t token_endpoint;
    ngx_str_t jwks_uri;
    ngx_str_t userinfo_endpoint;       /* 任意 */
} ngx_http_oidc_provider_metadata_t;

/* 共有メモリ上のセッション（oidc_session_store 有効時） */
typedef struct {
    ngx_rbtree_node_t  node;          /* node.key = セッション ID の crc32 */
    ngx_queue_t        queue;         /* LRU */
    time_t             expires;
    time_t             issued;
    time_t             access_expires;
    time_t             introspected;
    u_char             sid[64];
    u_short            id_token_len;
    u_short            access_token_len;
    u_short            refresh_token_len;
    u_short            claims_len;
    u_char             data[1];       /* claims || id_token || access || refresh */
} ngx_http_oidc_sess_t;

/* ロケーション単位の Discovery キャッシュ */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;
    ngx_pool_t                        *pool;     /* この世代の専用プール */
    time_t                             expires;  /* TTL 3600 秒 */
} ngx_http_oidc_cache_t;

/* main conf にはワーカー全体で共有する状態だけを置く */
typedef struct {
    u_char      hmac_secret[32];
    ngx_uint_t  secret_initialized:1;
    ngx_str_t   cookie_secret;
} ngx_http_oidc_main_conf_t;

/* ロケーション設定 */
typedef struct {
    ngx_flag_t   auth_oidc;
    ngx_str_t    oidc_provider;
    ngx_str_t    client_id;
    ngx_str_t    client_secret;
    ngx_str_t    redirect_uri;
    ngx_str_t    oidc_scope;
    ngx_flag_t   oidc_use_userinfo;
    time_t       session_timeout;
    ngx_array_t *session_claims;   /* oidc_claims の許可リスト（NULL なら既定） */

    ngx_str_t    logout_uri;                /* oidc_logout_uri */
    ngx_str_t    post_logout_redirect_uri;
    ngx_uint_t   client_auth_post;          /* oidc_client_auth post */
    ngx_flag_t   refresh_token;             /* oidc_refresh_token */
    ngx_flag_t   introspection;             /* oidc_introspection */
    time_t       introspection_interval;
    ngx_http_complex_value_t *auth_args;    /* oidc_auth_request_args */

    ngx_str_t    client_basic;     /* "Basic base64(id:secret)" を設定時に生成 */
    ngx_str_t    callback_path;    /* redirect_uri のパス部分 */
    ngx_http_oidc_cache_t *cache;  /* ロケーションごとのメタデータキャッシュ */
} ngx_http_oidc_loc_conf_t;

/* リクエストコンテキスト */
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  /* リクエストプールへのコピー */

    ngx_uint_t discovery_attempted:1;
    ngx_uint_t token_attempted:1;
    ngx_uint_t userinfo_attempted:1;
    ngx_uint_t waiting:1;      /* サブリクエスト連鎖が実行中 */
    ngx_uint_t done:1;         /* 連鎖が結果を出した */

    ngx_uint_t discovery_handled:1;   /* 各完了ハンドラの多重実行防止 */
    ngx_uint_t token_handled:1;
    ngx_uint_t jwks_handled:1;
    ngx_uint_t userinfo_handled:1;

    ngx_int_t  status;         /* done のときアクセスハンドラが返す値 */

    ngx_str_t  id_token;
    ngx_str_t  access_token;
    ngx_http_oidc_claims_t claims;
    ngx_array_t *extra_claims;

    /* 内部ロケーションへ変数で渡す値 */
    ngx_str_t  discovery_url, token_url, jwks_url, userinfo_url;
    ngx_str_t  token_body, token_basic, userinfo_bearer;
} ngx_http_oidc_ctx_t;
```

### 設計上のポイント

- **メタデータはロケーション単位**（`ngx_http_oidc_loc_conf_t.cache`）。main conf に 1 組だけ持つ実装では、複数の location に異なる `oidc_provider` を設定したときに先勝ちで混線するため。
- **キャッシュは世代ごとに専用プール**を持ち、再取得時に旧世代を解放する。リクエストはアクセスフェーズで `ngx_http_oidc_copy_metadata()` によりリクエストプールへコピーを取るため、解放が実行中のリクエストに影響しない。
- **内部ロケーションへ渡す値はすべてリクエストコンテキスト**に置き、変数ハンドラは `r->main` の ctx を読む。main conf に置くとリクエストをまたいで競合し、SSRF 対策としても不正確になる。
- **セッションの保存先は 2 通り**。既定ではクレームを HMAC 署名付き Cookie に載せる（ステートレス）。`oidc_session_store` を設定すると共有メモリの rbtree + LRU キューに保持し、Cookie には 256 bit の乱数 ID だけを載せる。ID トークン・アクセストークン・リフレッシュトークンは Cookie に載せるには大きすぎ、リフレッシュトークンはクライアントに渡すべきでないため、ログアウトの `id_token_hint`・トークン更新・イントロスペクションはストアモードを前提とする。
- **ストアの排他**は `ngx_slab_pool_t` のミューテックスで行い、ロード時はリクエストプールにコピーしてすぐロックを外す。満杯のときは期限切れ、次いで LRU の末尾から追い出す。

---

## 全体の処理フロー

```
ブラウザ                   NGINX（本モジュール）                IdP
   |                             |                                    |
   |─── GET /protected ─────────>|                                    |
   |                        [access_handler]                          |
   |                        キャッシュ無効 → Discovery 開始           |
   |                             |──── GET /_oidc_discovery ─────────>|
   |                             |<──── 200 JSON ─────────────────────|
   |                        issuer == oidc_provider を検証            |
   |                        メタデータをロケーションにキャッシュ      |
   |                             |                                    |
   |                        [access_handler 再実行]                   |
   |                        セッション Cookie なし                    |
   |                        → state / nonce / verifier を生成         |
   |<── 302 + Set-Cookie ────────|                                    |
   |                                                                  |
   |─── GET /authorize ──────────────────────────────────────────────>|
   |<── 302 /callback?code=...&state=... ────────────────────────────|
   |                                                                  |
   |─── GET /callback?code=... ─>|                                    |
   |                        callback_path と完全一致                  |
   |                        error パラメータ → 403                    |
   |                        state を CRYPTO_memcmp で検証 → 不一致 403|
   |                             |──── POST /_oidc_token ────────────>|
   |                             |     Authorization: Basic ...       |
   |                             |     body: grant_type/code/verifier |
   |                             |<──── 200 {id_token, ...} ──────────|
   |                             |──── GET /_oidc_jwks ──────────────>|
   |                             |<──── 200 JWKS ─────────────────────|
   |                        JWK → PEM を組み立て jwt_decode で署名検証|
   |                        iss/aud/azp/exp/iat/nonce を検証          |
   |                        （oidc_use_userinfo on の場合）           |
   |                             |──── GET /_oidc_userinfo ──────────>|
   |                             |<──── 200 {claims...} ──────────────|
   |                        sub の一致を確認しクレームをマージ        |
   |                        HMAC 署名付き Cookie を発行               |
   |<── 302 Location: /protected ─|                                   |
   |                                                                  |
   |─── GET /protected ──────────>|                                   |
   |                        Cookie の署名と発行時刻を検証             |
   |                        クレームを復元 → NGX_DECLINED             |
   |<── 200 OK ──────────────────|                                    |
```

---

## サブリクエスト連鎖の制御

本モジュールで最も注意を要するのが、アクセスフェーズから複数のサブリクエストを連鎖させる部分です。NGINX は**サブリクエストが finalize されるたびに親リクエストを posted_requests に積み、フェーズを再実行**します。したがって、

- token の完了ハンドラから JWKS サブリクエストを発行すると、その直後に親のアクセスフェーズが動く
- そのとき「処理中」を表現できないと、親は JWKS の結果を待たずにリクエストを終わらせてしまう

という問題が起きます。これを次の 2 点で制御しています。

1. **`ctx->waiting` / `ctx->done` / `ctx->status`**
   アクセスハンドラは先頭で、`done` なら確定した `status` を返し、`waiting` なら `NGX_AGAIN` を返して待機します（`ngx_http_oidc_access_handler`、行 2748 付近）。連鎖の各段は完了時に `ngx_http_oidc_finish()`（行 181）で結果を確定させます。`ngx_http_auth_request_module` の `ctx->done` と同じ考え方です。

2. **完了ハンドラの冪等化**
   NGINX は同じサブリクエストを複数回 finalize することがあり、そのたびに `post_subrequest` ハンドラが呼ばれます。実際、JWKS サブリクエストは 2 回 finalize され、素朴な実装では ID トークンの検証と UserInfo サブリクエストの発行が二重に走ります。`discovery_handled` / `token_handled` / `jwks_handled` / `userinfo_handled` のフラグで各ハンドラを 1 回だけ実行するようにしています。

Discovery だけはアクセスハンドラ自身から発行するため、完了時に `done` を立てず `waiting` を下ろすだけで、親はそのままフェーズを続行してキャッシュ済みメタデータで処理を進めます。

---

## 主要関数の解説

（行番号は目安です。実装の変更で前後します。）

### `ngx_http_oidc_access_handler`

アクセスフェーズの入口。順に判定します。

1. `auth_oidc` が有効でない、またはサブリクエスト自身 → `NGX_DECLINED`
2. `ctx->done` → 確定済みステータスを返す
3. `ctx->waiting` → `NGX_AGAIN`（連鎖の完了待ち）
4. 必須ディレクティブの未設定 → 500
5. メタデータ未取得または TTL 切れ → Discovery 開始（`NGX_AGAIN`）
6. URI が `logout_path` と完全一致 → ログアウト処理
7. URI が `callback_path` と**完全一致** → コールバック処理
8. セッションが有効な場合（ストアモードのみ）
   - アクセストークンが期限切れで `oidc_refresh_token on` → リフレッシュ開始（`NGX_AGAIN`）
   - `oidc_introspection on` かつ前回確認から `oidc_introspection_interval` 経過 → イントロスペクション開始（`NGX_AGAIN`）
9. セッションが有効 → クレームを復元して `NGX_DECLINED`
10. それ以外 → IdP へ 302

リフレッシュとイントロスペクションはコールバックではなく**通常のリクエスト**でサブリクエストを発行します。完了後は `done` を立てずに `waiting` を下ろすだけなので、親はそのままフェーズを続行し、更新後のセッションで再判定されます。

### `ngx_http_oidc_discovery_handler`（行 1152 付近）

Discovery 文書をパースし、`issuer` が `oidc_provider` と一致することを確認してからロケーションのキャッシュに格納します（OIDC Discovery 1.0 4.3）。新しい世代を専用プールに確保し、旧世代のプールを解放します。

### `ngx_http_oidc_redirect_to_idp`（行 1380 付近）

`RAND_bytes()` で 32 バイト × 3 を生成し、`state` / `nonce` / PKCE `code_verifier`（各 64 文字 HEX）とします。`code_challenge` は `BASE64URL(SHA256(verifier))`。認可エンドポイントが既にクエリを持つ場合は `&` で連結します。クエリ値の百分率エンコードは RFC 3986 の unreserved 集合を残す独自実装（`ngx_http_oidc_escape`、行 228）を使い、`ngx_escape_uri()` のテーブルより厳密にエンコードします。

発行する Cookie は `oidc_state` / `oidc_nonce` / `oidc_pkce_verifier` / `oidc_return_to` の 4 つで、いずれも `HttpOnly; Secure; SameSite=Lax; Path=/` かつ `Max-Age=600`。`oidc_return_to` は元 URI をエンコードして格納します（NGINX が渡す `r->uri` は復号済みで、Cookie 値に使えない文字を含みうるため）。

### `ngx_http_oidc_start_token_request`（行 1535 付近）

トークンリクエストのパラメータを組み立て、`ctx->token_body`（`proxy_set_body` 用）と `ctx->token_basic`（`Authorization` 用）に置いてサブリクエストを発行します。サブリクエストに引数を渡さないため、**認可コード・`code_verifier`・`client_secret` はリクエストラインに現れず、NGINX / IdP のログにも残りません**。クライアント認証は `client_secret_basic`（RFC 6749 2.3.1）です。

### `ngx_http_oidc_verify_signature`（行 1764 付近）

ID トークンの署名検証の中核です。

1. JOSE ヘッダを自前でデコードし `alg` と `kid` を取得（`ngx_http_oidc_jwt_header`、行 713）
2. `alg` を許可リストで確認（RS/PS/ES の 256/384/512 のみ。`none` と HS\* は拒否 — アルゴリズム混同攻撃対策）
3. JWKS から `kty` が対応し、`use` が `sig`、`kid` が一致する鍵を選択
4. JWK の `n`/`e`（RSA）または `crv`/`x`/`y`（EC）から SubjectPublicKeyInfo の DER を組み立て、PEM に変換（`oidc_jwk_rsa_to_pem` 行 564、`oidc_jwk_ec_to_pem` 行 635）
5. その PEM を鍵として `jwt_decode()` を呼ぶ

DER は OpenSSL の低レベル鍵 API を使わず手で組み立てています。OpenSSL 1.1 と 3.x で API が分かれており、3.x では `RSA_*` 系が deprecated で `-Werror` ビルドが通らないためです。

> **注意**: libjwt 1.x の `jwt_decode()` は第 4 引数 `key_len` に 0 を渡すと「鍵なし」と解釈し、**署名検証を行いません**。JWKS の JSON をそのまま渡す使い方は成立しないため、上記のように公開鍵を組み立てる必要があります。

### `ngx_http_oidc_validate_claims`（行 1889 付近）

OIDC Core 3.1.3.7 に従い、`iss`（Discovery の `issuer` と一致）、`aud`（`client_id` を含む。文字列・配列の両方に対応）、`azp`（`aud` が複数のとき必須）、`exp`（未来であること）、`iat`（未来でないこと）、`nonce`（Cookie と定時間比較）を検証します。クロックスキューは ±60 秒。

### `ngx_http_oidc_merge_claims` / `ngx_http_oidc_claim_to_str`（行 1013 / 815 付近）

ID トークンと UserInfo のクレームを取り込みます。文字列・整数・実数・真偽値に加え、**配列はカンマ区切りに展開**します（Keycloak や Entra ID の `groups` / `roles` はしばしば配列で返るため）。プロトコルクレーム（`iss` `aud` `exp` `iat` `nbf` `jti` `nonce` `azp` `at_hash` `c_hash` `s_hash` `auth_time` `sid` `typ` `session_state`）と、専用フィールドを持つ `sub` / `email` / `name` は `extra_claims` に入れません。`oidc_claims` を設定した場合はその許可リストのみを取り込みます。

### リフレッシュとイントロスペクション

`ngx_http_oidc_start_refresh_request()` は `grant_type=refresh_token` でトークンエンドポイントに問い合わせます。`ctx->phase` が `OIDC_PHASE_REFRESH` のとき、

- 新しい ID トークンが返れば JWKS で署名を検証し、`iss` / `aud` / `exp` に加えて **`sub` が元のセッションと一致すること**を確認します（`nonce` は認可リクエストのものなので検証しません）
- ID トークンが返らない場合はクレームをそのままにトークンだけを差し替えます
- 失敗した場合はセッションを破棄し、通常の再認証にフォールバックします（ユーザーにはエラーを見せません）

`ngx_http_oidc_start_introspect_request()` は RFC 7662 のイントロスペクションを行い、`active: false` ならセッションを破棄します。エンドポイントに到達できない場合はセッションを残し（フェイルオープン）、確認時刻を更新しないので次のリクエストで再試行します。

### `ngx_http_oidc_logout`

セッションを破棄して Cookie を消し、IdP の `end_session_endpoint` へ `client_id`・`id_token_hint`（ストアモードのみ）・`post_logout_redirect_uri` を付けてリダイレクトします。`end_session_endpoint` が無い IdP ではローカルのセッションだけを消して `oidc_post_logout_redirect_uri` へ戻します。

### `ngx_http_oidc_userinfo_handler`（行 2206 付近）

UserInfo レスポンスの `sub` が ID トークンの `sub` と一致することを確認してからクレームをマージします（OIDC Core 5.3.2）。UserInfo の失敗は致命的ではなく、ID トークンのクレームだけでセッションを発行します。

### `ngx_http_oidc_issue_session_and_redirect`（行 2303 付近）

セッション Cookie のペイロード:

```
B64(sub):B64(email):B64(name):issued_at[|B64(key):B64(val)]...
```

これを HMAC-SHA256 で署名し、`oidc_auth` Cookie として `Max-Age=oidc_session_timeout` 付きで発行します。ログイン処理用の 4 つの Cookie は削除し、`oidc_return_to` の値をデコードして 302 でリダイレクトします。戻り先は**ローカルパスのみ**を許可し、`//host` や `/\host`（プロトコル相対 URL によるオープンリダイレクト）と制御文字を含む値は拒否して `/` にフォールバックします。

### `ngx_http_oidc_verify_session`（行 2494 付近）

`oidc_auth` Cookie の先頭 64 文字の HMAC を `CRYPTO_memcmp()` で定時間比較し、ペイロードの `issued_at` を `oidc_session_timeout` と照合します。期限切れ・未来日時・署名不一致はいずれも「未認証」として扱われ、IdP への再認証リダイレクトになります。検証を通れば固定クレームと任意クレームを復元します。

### `ngx_http_oidc_init_process`（行 3228 付近）

ワーカー起動時に一度だけ実行され、`oidc_cookie_secret` を SHA-256 で 32 バイトに畳んで HMAC 鍵にします（任意長の設定値を受け付けるため）。未設定の場合はワーカーごとのランダム鍵を生成し `WARN` を出力します。

---

## エラー時のステータスコード

| 状況 | ステータス |
|------|-----------|
| IdP がコールバックで `error` を返した | 403 |
| コールバックに `code` / `state` が無い | 400 |
| `state` が Cookie と一致しない | 403 |
| ID トークンの署名・`iss`・`aud`・`exp`・`nonce` が不正 | 401 |
| Discovery / トークン / JWKS の取得や JSON パースに失敗 | 502 |
| 設定不備・メモリ確保失敗 | 500 |

UserInfo の失敗のみ非致命的（警告ログを出して ID トークンのクレームで続行）です。

---

## 公開 NGINX 変数

| 変数名 | 内容 |
|--------|------|
| `$oidc_claim_sub` / `$oidc_claim_email` / `$oidc_claim_name` | 固定クレーム。継続アクセスでも Cookie から復元 |
| `$oidc_claim_<name>` | 任意クレーム。継続アクセスでも Cookie から復元 |
| `$oidc_access_token` | アクセストークン（初回認証リクエストのみ） |
| `$oidc_discovery_url` / `$oidc_token_url` / `$oidc_jwks_url` / `$oidc_userinfo_url` | 内部ロケーションの `proxy_pass` 用 |
| `$oidc_token_body` | トークンリクエストのボディ（`proxy_set_body` 用） |
| `$oidc_token_basic` | `Basic base64(client_id:client_secret)` |
| `$oidc_userinfo_bearer` | `Bearer <access_token>` |

---

## 運用上の注意

- **`resolver` が必須**: `proxy_pass $oidc_*_url` は upstream を実行時に解決するため、IdP のエンドポイントがホスト名なら `resolver` が無いと失敗します。
- **upstream の TLS 検証**: NGINX の既定では `proxy_ssl_verify` は off です。HTTPS の IdP を使う場合は内部ロケーションで必ず有効化してください。無効のままだと、トークンエンドポイントへの中間者攻撃で ID トークンを差し替えられる余地が残ります。
- **`proxy_set_header Content-Length "";` を書かない**: `proxy_set_body` が設定する Content-Length が消え、トークンリクエストのボディが IdP に届きません。
- **`oidc_cookie_secret` の設定**: 未設定だとワーカーごとに鍵が異なり、セッションがワーカー切り替えやリロードで無効になります。

---

## 残存する課題

| 機能 | 説明 |
|------|------|
| Back-Channel / Front-Channel Logout | IdP からの通知でセッションを破棄する方式。現状は RP-Initiated Logout のみ |
| 外部セッションストア（Redis 等） | 共有メモリはホスト内で共有される。複数ホスト間で共有するには外部ストアが必要 |
| `private_key_jwt` / `client_secret_jwt` | クライアント認証は `client_secret_basic` と `client_secret_post` のみ |
| `oidc_provider` ブロック構文 | NGINX Plus モジュールとの設定互換 |
