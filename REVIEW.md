# NGINX OIDC モジュール — ソースコードレビュー

## 概要

`ngx_http_oidc_module` は、NGINX Open Source に OpenID Connect (OIDC) 認証機能を追加する C 言語製のダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現することを目的とし、OAuth 2.0 Authorization Code Flow を実装します。

ソースは単一ファイル `ngx_http_oidc_module.c`（2177 行）にまとめられており、以下の外部ライブラリに依存します。

| ライブラリ | 用途 |
|------------|------|
| OpenSSL (libssl / libcrypto) | 乱数生成・HMAC-SHA256・SHA-256・定時間比較 |
| Jansson | JSON パース（ディスカバリ・トークンレスポンス・JWT クレーム） |
| libjwt (>= 1.15.3) | JWT デコード・署名検証 |

---

## ファイル構成

```
nginx-oidc/
├── ngx_http_oidc_module.c   # メインソース（2177 行）
├── config                   # NGINX モジュールビルド設定
├── README.md                # 要件定義
├── REVIEW.md                # 本ファイル
└── test/                    # E2E テストスイート
    ├── e2e.spec.js          # Playwright E2E テスト
    ├── mock-idp.js          # モック IdP（Express + RS256 JWT 署名）
    ├── nginx_mock.js        # NGINX 起動ヘルパー
    ├── nginx.conf           # テスト用 NGINX 設定
    ├── playwright.config.js # Playwright 設定
    └── package.json         # テスト依存関係
```

---

## データ構造

```c
// OIDCプロバイダのエンドポイント情報（Discoveryから取得）
typedef struct {
    ngx_str_t authorization_endpoint;  // 認可エンドポイントURL
    ngx_str_t token_endpoint;          // トークンエンドポイントURL
    ngx_str_t jwks_uri;                // JWKSエンドポイントURL
    ngx_str_t userinfo_endpoint;       // UserInfoエンドポイントURL（任意）
} ngx_http_oidc_provider_metadata_t;

// IDトークンから抽出したクレーム
typedef struct {
    ngx_str_t sub;    // ユーザー識別子
    ngx_str_t email;  // メールアドレス
    ngx_str_t name;   // 表示名
} ngx_http_oidc_claims_t;

// 任意クレームのキーバリューエントリ（$oidc_claim_* プレフィックス変数向け）
typedef struct {
    ngx_str_t key;
    ngx_str_t value;
} ngx_http_oidc_claim_entry_t;

// グローバル設定（ワーカープロセス内でキャッシュ）
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  // プロバイダメタデータ
    time_t discovery_expires;                      // キャッシュ有効期限（TTL: 3600秒）
    u_char hmac_secret[32];                        // セッションCookie署名用秘密鍵
    ngx_uint_t secret_initialized:1;               // 秘密鍵初期化済みフラグ
    ngx_str_t cookie_secret;                       // oidc_cookie_secret ディレクティブで設定した共有シークレット
    ngx_str_t discovery_url;                       // SSRF対策用ディスカバリURL（proxy_passで使用）
    ngx_str_t userinfo_url;                        // SSRF対策用UserInfo URL（proxy_passで使用）
} ngx_http_oidc_main_conf_t;

// ロケーション設定（nginx.conf から読み込み）
typedef struct {
    ngx_flag_t  auth_oidc;           // OIDC認証の有効/無効
    ngx_str_t   oidc_provider;       // プロバイダのベースURL
    ngx_str_t   client_id;           // OAuthクライアントID
    ngx_str_t   client_secret;       // OAuthクライアントシークレット
    ngx_str_t   redirect_uri;        // コールバックURI
    ngx_str_t   oidc_scope;          // OAuthスコープ（デフォルト: "openid"）
    ngx_flag_t  oidc_use_userinfo;   // UserInfoエンドポイント呼び出し有効/無効
} ngx_http_oidc_loc_conf_t;

// リクエストコンテキスト（リクエスト単位で保持）
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  // メタデータへのポインタ
    ngx_uint_t discovery_attempted:1;              // ディスカバリ試行済みフラグ
    ngx_uint_t token_attempted:1;                  // トークン取得試行済みフラグ
    ngx_uint_t userinfo_attempted:1;               // UserInfo取得試行済みフラグ
    ngx_uint_t redirect_issued:1;                  // 302レスポンスヘッダ設定済みフラグ
    ngx_str_t id_token;                            // 取得したIDトークン文字列
    ngx_str_t access_token;                        // $oidc_access_token 変数向けアクセストークン
    ngx_http_oidc_claims_t claims;                 // 検証済みクレーム
    ngx_array_t *extra_claims;                     // 任意クレームの配列（$oidc_claim_* 変数向け）
} ngx_http_oidc_ctx_t;
```

- **`ngx_http_oidc_main_conf_t`** はワーカープロセス起動時に確保され、プロバイダメタデータのキャッシュおよび HMAC 秘密鍵を保持します。`cookie_secret` は `oidc_cookie_secret` ディレクティブで設定した生の文字列を保持し、`init_process` フックで `hmac_secret` に転写されます。
- **`ngx_http_oidc_loc_conf_t`** は設定ファイル読み込み時に確定し、ロケーションごとの OIDC 設定を保持します。
- **`ngx_http_oidc_ctx_t`** はリクエストプールに確保され、リクエストが終わると解放されます。`redirect_issued` フラグは `ngx_http_oidc_issue_session_and_redirect` が 302 ヘッダを設定した後にセットされ、アクセスハンドラが `NGX_HTTP_MOVED_TEMPORARILY` を返す判断に使います（"header already sent" 問題を防止）。
- **`ngx_http_oidc_claim_entry_t`** は JWT クレームや UserInfo レスポンスの任意フィールドを保持し、`ctx->extra_claims` 配列に格納されます。セッション Cookie にも永続化されるため、継続アクセスリクエストでも利用可能です。

---

## 全体の処理フロー

```
ブラウザ                   NGINX（本モジュール）                IdP（Keycloak等）
   |                             |                                    |
   |─── GET /protected ─────────>|                                    |
   |                        [access_handler]                          |
   |                        mcf->metadata == NULL?                    |
   |                             |──── GET /_oidc_discovery ─────────>|
   |                             |    ?url=.../openid-configuration   |
   |                             |<──── 200 JSON ─────────────────────|
   |                        [discovery_handler]                       |
   |                        JSON をパースして mcf->metadata に保存    |
   |                        discovery_expires = now + 3600 をセット   |
   |                        親リクエストを再開                        |
   |                             |                                    |
   |                        [access_handler 再実行]                   |
   |                        oidc_auth Cookie なし？                   |
   |                        → state / nonce / PKCE verifier を RAND_bytes で生成
   |                        → 元リクエスト URI を oidc_return_to Cookie に保存
   |<── 302 + Set-Cookie ────────|                                    |
   |   (oidc_state=HEX64; HttpOnly; Secure; SameSite=Lax)            |
   |   (oidc_nonce=HEX64; HttpOnly; Secure; SameSite=Lax)            |
   |   (oidc_pkce_verifier=HEX64; HttpOnly; Secure; SameSite=Lax)   |
   |   (oidc_return_to=/protected; HttpOnly; Secure; SameSite=Lax)   |
   |                                                                  |
   |─── GET /authorize ──────────────────────────────────────────────>|
   |   ?response_type=code&scope=openid&client_id=...                 |
   |   &redirect_uri=...&state=HEX64&nonce=HEX64                     |
   |   &code_challenge=B64URL(SHA256(verifier))&code_challenge_method=S256
   |                         （ユーザーがIdPでログイン）              |
   |<── 302 /callback?code=AUTH_CODE&state=HEX64 ────────────────────|
   |                                                                  |
   |─── GET /callback?code=...&state=HEX64 ─────────────────────────>|
   |                        [access_handler]                          |
   |                        URI == redirect_uri ?                     |
   |                        state パラメータ ≠ oidc_state Cookie      |
   |                          → 403 Forbidden                        |
   |                        一致 → トークンリクエスト開始            |
   |                             |──── POST /_oidc_token ────────────>|
   |                             |    code=...&client_id=...          |
   |                             |    &code_verifier=HEX64            |
   |                             |<──── 200 JSON ─────────────────────|
   |                        [token_handler]                           |
   |                        id_token を ctx に保存                    |
   |                        → JWKS 取得サブリクエスト開始            |
   |                             |──── GET /_oidc_jwks ──────────────>|
   |                             |    ?url=.../certs                  |
   |                             |<──── 200 JWKS JSON ────────────────|
   |                        [jwks_handler]                            |
   |                        jwt_decode() で署名検証                   |
   |                        exp クレーム確認（有効期限）              |
   |                        nonce クレーム ≠ oidc_nonce Cookie        |
   |                          → エラーログ                           |
   |                        sub / email / name + 全JWTクレームを ctx に保存
   |                        oidc_use_userinfo on? → UserInfo取得へ   |
   |                             |──── GET /_oidc_userinfo ──────────>|
   |                             |    Authorization: Bearer access_token
   |                             |<──── 200 JSON ─────────────────────|
   |                        [userinfo_handler]                        |
   |                        UserInfoクレームを extra_claims にマージ  |
   |                        HMAC-SHA256(payload) で oidc_auth Cookie 発行
   |                        oidc_state / oidc_nonce / oidc_pkce_verifier / oidc_return_to Cookie を削除
   |<── 302 Location: /protected ─|                                   |
   |   Set-Cookie: oidc_auth=HMAC_HEX+PAYLOAD; HttpOnly; Secure; SameSite=Lax; Path=/
   |                                                                  |
   |─── GET /protected ──────────>|                                   |
   |                        [access_handler]                          |
   |                        oidc_auth Cookie を取得                   |
   |                        CRYPTO_memcmp() で HMAC 署名を検証        |
   |                        sub / email / name + 任意クレームを ctx->claims に復元
   |                        → NGX_DECLINED（通過）                   |
   |<── 200 OK ──────────────────|                                    |
```

---

## 主要関数の解説

### `ngx_http_oidc_get_cookie`（行 138–200）

Cookie ヘッダを走査して指定名の Cookie 値を返す共通ヘルパー関数です。以前は Cookie の検索ロジックが 3 箇所に重複していましたが、この関数に集約されています。`name=` プレフィックスで前方一致検索を行い、`;` で区切られた Cookie の値を `ngx_str_t` に格納して返します。

---

### `ngx_http_oidc_access_handler`（行 1625–1871）

HTTP アクセスフェーズで呼び出されるメイン関数です。以下の順で判定します。

1. `auth_oidc` が無効、またはサブリクエスト自身 (`r != r->main`) → `NGX_DECLINED`（スキップ）
2. `mcf->discovery_expires` が期限切れ → メタデータを破棄して再取得フローへ
3. `mcf->metadata` が未取得かつ `discovery_attempted` が立っていない → ディスカバリ開始 (`NGX_AGAIN`)
4. `discovery_attempted` が立っているのにメタデータがない → 500 エラー（同一リクエスト内でのリトライ防止）
5. URI がコールバックパス (`redirect_uri`) に一致 → `state` 検証 → トークン取得開始
6. `redirect_issued` フラグが立っている → `NGX_HTTP_MOVED_TEMPORARILY` を返す（"header already sent" 防止）
7. `oidc_auth` Cookie の HMAC 検証成功 → セッション Cookie から sub/email/name と任意クレームを復元 → `NGX_DECLINED`（認証済みとして通過）
8. 上記以外（未認証） → `ngx_http_oidc_redirect_to_idp` で IdP へ 302 リダイレクト

`redirect_issued` フラグは `ngx_http_oidc_issue_session_and_redirect` が 302 ヘッダを `r->headers_out` に書き込んだ後にセットされます。親リクエストのフェーズが再開された際にアクセスハンドラはこのフラグを見て `NGX_HTTP_MOVED_TEMPORARILY` を返し、コンテントフェーズ（`proxy_pass`）に落ちないようにします。

---

### `ngx_http_oidc_start_discovery` / `ngx_http_oidc_discovery_handler`（行 292–349 / 202–291）

NGINX のサブリクエスト機構を使い `/_oidc_discovery` 内部ロケーションへ非同期リクエストを送ります。`ngx_http_post_subrequest_t` にコールバック関数を登録し `NGX_AGAIN` を返すことで、イベントループをブロックせずにレスポンスを待ちます。

完了ハンドラ `ngx_http_oidc_discovery_handler` では Jansson の `json_loadb()` で JSON をパースし、3 つのエンドポイント URL を `mcf->metadata`（グローバルプール）へコピーします。成功後は `mcf->discovery_expires = ngx_time() + 3600` でキャッシュ TTL を設定し、`r->parent->write_event_handler = ngx_http_core_run_phases` で親リクエストのフェーズ処理を再開させます。

---

### `ngx_http_oidc_parse_discovery_json`（行 350–415）

`authorization_endpoint`・`token_endpoint`・`jwks_uri`・`userinfo_endpoint` の 4 フィールドを抽出します。各文字列は `ngx_cycle->pool`（ワーカー生存期間中有効なグローバルプール）に確保されるため、リクエスト終了後もメタデータが保持されます。

---

### `ngx_http_oidc_redirect_to_idp`（行 1404–1620）

`RAND_bytes()` で 32 バイトの乱数を 3 つ生成し、それぞれ 64 文字の HEX 文字列（`state`・`nonce`・PKCE `code_verifier`）に変換します。`client_id`・`redirect_uri`・`scope` は `ngx_escape_uri()` でパーセントエンコードしたうえで認可エンドポイント URL に付加します。PKCE の `code_challenge` は `BASE64URL(SHA256(verifier))` で計算し、`code_challenge_method=S256` とともに URL に付加します。

以下の 4 つの Cookie を発行して 302 レスポンスを返します（すべて `HttpOnly; Secure; SameSite=Lax; Path=/`）。

| Cookie 名 | 内容 |
|-----------|------|
| `oidc_state` | CSRF 防止用の state 値 (64文字 HEX) |
| `oidc_nonce` | リプレイ攻撃防止用の nonce 値 (64文字 HEX) |
| `oidc_pkce_verifier` | PKCE code_verifier (64文字 HEX) |
| `oidc_return_to` | 認証後のリダイレクト先 URI（最大 2048 バイト、クエリ文字列含む） |

---

### `ngx_http_oidc_token_handler` / `ngx_http_oidc_start_token_request`（行 549–648 / 1308–1403）

トークンエンドポイントへの POST を模倣するため、`code`・`client_id`・`client_secret`・`redirect_uri`・`grant_type`・`code_verifier` をクエリストリング形式で組み立て、`/_oidc_token` 内部ロケーションへサブリクエストを発行します（nginx.conf 側で `proxy_set_body $args` によって POST ボディに変換）。

完了ハンドラ `ngx_http_oidc_token_handler` では JSON から `id_token` と `access_token` の両方を確認します。`id_token` のみを必須とし（`access_token` はオプション）、両者を `ctx` に保存した後、引き続き JWKS 取得サブリクエストを連鎖させます。

---

### `ngx_http_oidc_jwks_handler` / `ngx_http_oidc_start_jwks_request`（行 687–876 / 649–686）

`/_oidc_jwks` 内部ロケーション経由で `jwks_uri` から JWKS JSON を取得し、libjwt の `jwt_decode()` に渡します。この関数は JWT の署名をインラインで検証します。検証成功後は以下の順で処理します。

1. `exp` クレームで有効期限を確認（`ngx_time()` との比較）
2. `oidc_nonce` Cookie と JWT の `nonce` クレームを比較してリプレイ攻撃を防止
3. `sub`・`email`・`name` を `ctx->claims` に保存
4. JWT の全クレームを `ctx->extra_claims` 配列に保存（文字列・整数クレームを対象）
5. `oidc_use_userinfo on` かつ `access_token` が取得済みの場合は UserInfo サブリクエストへ委譲
6. UserInfo を使わない場合は `ngx_http_oidc_issue_session_and_redirect` を直接呼び出す

---

### `ngx_http_oidc_issue_session_and_redirect`（行 894–1079）

セッション Cookie の発行と 302 リダイレクトを担う共通関数です。`jwks_handler` と `userinfo_handler` の両方から呼び出されます。

Cookie ペイロード形式:
```
B64(sub):B64(email):B64(name):timestamp[|B64(key1):B64(val1)|B64(key2):B64(val2)...]
```

処理の流れ:
1. `sub`・`email`・`name` を `ngx_encode_base64()` でエンコードしてベースペイロードを構築
2. `ctx->extra_claims` の各エントリを `|B64(key):B64(val)` 形式で追記（合計 `OIDC_SESSION_MAX_PAYLOAD = 3500` バイト上限）
3. `HMAC(EVP_sha256(), hmac_secret, payload)` で署名し `oidc_auth` Cookie を発行
4. `oidc_state`・`oidc_nonce`・`oidc_pkce_verifier`・`oidc_return_to` Cookie を過去日付で削除
5. `oidc_return_to` Cookie の値（元リクエスト URI）に 302 リダイレクト
6. `ctx->redirect_issued = 1` をセットしてアクセスハンドラに通知

---

### `ngx_http_oidc_userinfo_handler` / `ngx_http_oidc_start_userinfo_request`（行 1089–1251 / 1253–1307）

`/_oidc_userinfo` 内部ロケーション経由で `userinfo_endpoint` へ `Authorization: Bearer <access_token>` を付けてリクエストします。

完了ハンドラ `ngx_http_oidc_userinfo_handler` は JSON レスポンスを Jansson でパースし、返却された各クレームを `ctx->extra_claims` にマージ（または追記）します。`sub`・`email`・`name` が含まれる場合は固定クレームも更新します。完了後は `ngx_http_oidc_issue_session_and_redirect` を呼び出してセッション Cookie を発行します。UserInfo 取得失敗時はフォールバックとして JWT クレームのみで Cookie を発行（非致命的エラー）。

---

### セッション Cookie の検証（行 1740–1861）

`oidc_auth` Cookie の形式は `HMAC_HEX(64文字) + PAYLOAD` です。アクセスハンドラはペイロード部分に対して同じ HMAC を計算し、`CRYPTO_memcmp()` で定時間比較を行います。Cookie 先頭 64 文字と一致すれば、ペイロードを解析して以下を復元します：

- `B64(sub):B64(email):B64(name):timestamp` → 固定クレームを `ctx->claims` に格納
- `|B64(key):B64(val)|...` セクション → 任意クレームを `ctx->extra_claims` 配列に格納

これにより継続アクセスでも `$oidc_claim_sub`・`$oidc_claim_email`・`$oidc_claim_name` に加え、`$oidc_claim_groups` 等の任意クレーム変数もすべて利用可能です。

---

### `ngx_http_oidc_init_process`（行 2039–2071）

ワーカープロセス起動時に一度だけ呼び出される `init_process` フックです。`oidc_cookie_secret` ディレクティブが設定されている場合はその値を `hmac_secret` に転写し、すべてのワーカー間で同一のシークレットを使用します。未設定の場合は `RAND_bytes()` でランダムシークレットを生成しますが、マルチワーカー構成では Cookie の互換性が失われる旨を `WARN` レベルでログ出力します。

---

## nginx.conf 設定例

```nginx
load_module modules/ngx_http_oidc_module.so;

http {
    # マルチワーカー構成では必須。全ワーカーで同一の HMAC シークレットを使用する。
    # openssl rand -hex 32 で生成した値を設定すること。
    oidc_cookie_secret "your-random-secret-here";

    server {
        listen 80;

        # Discovery サブリクエスト用（SSRF 対策: $oidc_discovery_url 変数を使用）
        # $oidc_discovery_url は oidc_provider 設定値から組み立てた URL を返す
        location = /_oidc_discovery {
            internal;
            proxy_pass $oidc_discovery_url;
        }

        # Token エンドポイント用（POST ボディに変換）
        location = /_oidc_token {
            internal;
            proxy_pass http://idp.example.com/realms/myrealm/protocol/openid-connect/token;
            proxy_method POST;
            proxy_set_header Content-Type "application/x-www-form-urlencoded";
            proxy_set_body $args;
        }

        # JWKS サブリクエスト用（SSRF 対策: $oidc_jwks_url 変数を使用）
        # $oidc_jwks_url は Discovery で取得した jwks_uri を返す
        location = /_oidc_jwks {
            internal;
            proxy_pass $oidc_jwks_url;
        }

        # UserInfo サブリクエスト用（SSRF 対策: $oidc_userinfo_url 変数を使用）
        # $oidc_userinfo_url は Discovery で取得した userinfo_endpoint を返す
        # oidc_use_userinfo on; が必要
        location = /_oidc_userinfo {
            internal;
            proxy_pass $oidc_userinfo_url;
            proxy_set_header Authorization "Bearer $arg_token";
        }

        # 保護するロケーション
        location / {
            auth_oidc          on;
            oidc_provider      "https://idp.example.com/realms/myrealm";
            oidc_client_id     "my-client";
            oidc_client_secret "secret";
            oidc_redirect_uri  "/callback";
            oidc_scope         "openid profile email";  # デフォルト: "openid"
            # oidc_use_userinfo on;   # UserInfoエンドポイントから追加クレームを取得する場合

            proxy_pass http://backend;
            proxy_set_header X-Remote-User   $oidc_claim_sub;
            proxy_set_header X-Remote-Email  $oidc_claim_email;
            proxy_set_header X-Remote-Name   $oidc_claim_name;
            # 任意クレーム変数（初回認証・継続アクセス双方でセッションCookieから利用可能）:
            # proxy_set_header X-Remote-Groups  $oidc_claim_groups;
            # proxy_set_header X-Tenant-ID      $oidc_claim_tenant_id;
            # アクセストークンをバックエンドに渡す場合（初回認証リクエストのみ）:
            # proxy_set_header Authorization "Bearer $oidc_access_token";
        }
    }
}
```

---

## 公開 NGINX 変数

| 変数名 | 内容 |
|--------|------|
| `$oidc_claim_sub` | JWT の `sub` クレーム（ユーザーID）。継続アクセスでも Cookie から復元 |
| `$oidc_claim_email` | JWT の `email` クレーム。継続アクセスでも Cookie から復元 |
| `$oidc_claim_name` | JWT の `name` クレーム。継続アクセスでも Cookie から復元 |
| `$oidc_claim_<name>` | JWT / UserInfo の任意クレーム。**継続アクセスでも Cookie から復元**（例: `$oidc_claim_groups`, `$oidc_claim_roles`, `$oidc_claim_tenant_id`） |
| `$oidc_access_token` | アクセストークン（初回認証リクエストのみ有効） |
| `$oidc_discovery_url` | SSRF 対策用ディスカバリ URL（`proxy_pass` で使用） |
| `$oidc_jwks_url` | SSRF 対策用 JWKS URL（`proxy_pass` で使用） |
| `$oidc_userinfo_url` | SSRF 対策用 UserInfo URL（`proxy_pass` で使用） |

**継続認証（`oidc_auth` Cookie による再訪問）** では、セッション Cookie のペイロードに `B64(sub):B64(email):B64(name):timestamp[|B64(key):B64(val)...]` を含めているため、**固定クレームと任意クレームの両方**がセッション Cookie から復元されます（クッキーサイズ上限: 3500 バイト）。

**`$oidc_access_token` 変数** は初回認証リクエスト時のみ有効です（`token_handler` でのみ設定）。継続アクセスでは空になります。

---

## 改善点

### 解決済みの問題

以下の問題は現在の実装で対処済みです。

| 番号 | 問題 | 対処内容 |
|------|------|---------|
| 1 | HMAC シークレットがマルチワーカー環境で共有されない | `oidc_cookie_secret` ディレクティブ追加。`init_process` フックで全ワーカーに同一シークレットを配布 |
| 2 | Cookie 検証中にシークレットを再生成してしまう | `init_process` フックで起動時に一度だけ初期化。Cookie 発行・検証時は再生成しない |
| 3 | セッション Cookie に email と name が含まれない | ペイロードを `B64(sub):B64(email):B64(name):timestamp` 形式に変更。継続アクセスで 3 変数すべて復元可能 |
| 4 | 認証後のリダイレクト先が常に `/` に固定 | `oidc_return_to` Cookie に元リクエスト URI（クエリ文字列含む）を保存し、認証後に復元 |
| 5 | Cookie パース処理が複数箇所に重複 | `ngx_http_oidc_get_cookie()` ヘルパー関数に集約 |
| 6 | ディスカバリキャッシュの有効期限が機能していない | `discovery_expires = ngx_time() + 3600` を設定。アクセスハンドラで TTL チェックして期限切れ時に再取得 |
| 7 | `proxy_pass $arg_url` による SSRF リスク | `$oidc_discovery_url` / `$oidc_jwks_url` / `$oidc_userinfo_url` 変数を追加。nginx.conf でこれらの変数を `proxy_pass` に使用することで URL の出所を設定値に限定 |
| 8 | Cookie に `Secure` 属性がない | すべての Cookie に `; HttpOnly; Secure; SameSite=Lax; Path=/` を付加 |
| 9 | Cookie に `SameSite` 属性がない | 同上 |
| 10 | HMAC 比較がタイミング攻撃に脆弱 | `ngx_strncmp()` を `CRYPTO_memcmp()` に置き換え |
| 11 | Cookie ペイロードのデリミタ問題 | `ngx_encode_base64()` で sub/email/name をエンコード。`:` を含む name クレームでも正しく解析可能 |
| 12 | `oidc_return_to` Cookie にクエリ文字列が含まれない | `r->uri + '?' + r->args` を連結して保存。2048 バイト制限内に収める |
| 13 | `access_token` 必須チェックが IdP 互換性を損なう | `id_token` のみを必須とし、`access_token` はオプションとして扱うよう変更 |
| 14 | 認証後に `proxy_pass` コンテントフェーズへ落ちて "header already sent" エラー | `ctx->redirect_issued` フラグを追加。302 ヘッダ設定済みの場合はアクセスハンドラが `NGX_HTTP_MOVED_TEMPORARILY` を返してコンテントフェーズをスキップ |

---

### 実装済みの機能

| 機能 | 実装状況 |
|------|---------|
| PKCE | 実装済み。`code_verifier` を生成して `oidc_pkce_verifier` Cookie に保存し、`code_challenge=S256` を認可リクエストに付加。トークンリクエスト時に `code_verifier` を送信 |
| スコープ設定 (`oidc_scope`) | 実装済み。デフォルト `"openid"`。`oidc_scope "openid profile email"` 形式で設定可能 |
| `$oidc_access_token` 変数 | 実装済み。`proxy_set_header Authorization "Bearer $oidc_access_token"` で利用可能（初回認証時のみ） |
| UserInfo エンドポイント | 実装済み。`oidc_use_userinfo on` で有効化。Google/Microsoft 等の最小クレーム IdP に対応 |
| 任意クレーム変数 (`$oidc_claim_<name>`) | 実装済み。JWT クレームおよび UserInfo クレームを `extra_claims` 配列で管理。継続アクセスでも Cookie から復元 |
| セッション Cookie への任意クレーム永続化 | 実装済み。`extra_claims` を `|B64(key):B64(val)` 形式でセッション Cookie に格納。3500 バイト上限 |
| E2E テストスイート | 実装済み。Playwright + モック IdP (Express + RS256) による自動テスト。`groups`・`tenant_id` クレームの継続アクセスでの復元も検証 |

---

### 残存する課題

| 機能 | 説明 |
|------|------|
| RP-Initiated Logout | IdP の `/logout` エンドポイントへのリダイレクト |
| リフレッシュトークン | アクセストークンの自動更新 |
| Token Introspection | IdP への失効確認 |
| 複数プロバイダ対応 | ロケーションごとに異なる IdP を設定 |
| SSL/TLS 設定 (`oidc_ssl_trusted_certificate`) | 自己署名証明書・内部 CA 環境での信頼性確保 |

---

## 実装フェーズの現状

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | 完了 |
| Phase 2 | OIDC Discovery（非同期サブリクエスト） | 完了 |
| Phase 3 | 認証フロー・トークン交換・state 検証・PKCE | 完了 |
| Phase 4 | JWT 署名検証・nonce 検証・セッション Cookie 発行・任意クレーム変数・UserInfo 対応 | 完了 |
| Phase 5 | テスト・最適化 | 部分完了（Playwright E2E テスト実装済み。共有メモリキャッシュ・リフレッシュトークン等は未着手） |

---

## 対応優先度

既存バグの修正・未実装機能の追加について、セキュリティ影響度・実用デプロイでの必要性・実装コストを軸に優先度を設定します。

### P0 — セキュリティ上必須（対応済み）

| 項目 | 状態 |
|------|------|
| **PKCE 実装** | 完了。S256 メソッドで実装。`oidc_pkce_verifier` Cookie に verifier を保存し、認証後に削除 |
| **SSRF 対策強化**（問題 7） | 完了。`$oidc_discovery_url` / `$oidc_jwks_url` / `$oidc_userinfo_url` 変数を追加 |

### P1 — 実用デプロイに不可欠（対応済み）

| 項目 | 状態 |
|------|------|
| **`access_token` チェックの緩和**（問題 13） | 完了。`id_token` のみ必須。`access_token` は取得できた場合のみ `$oidc_access_token` に格納 |
| **スコープ設定ディレクティブ (`oidc_scope`)** | 完了。デフォルト `"openid"`。任意スコープを設定可能 |
| **`$oidc_access_token` 変数** | 完了。Bearer トークン転送が可能（初回認証リクエストのみ） |
| **Cookie ペイロードのデリミタ問題修正**（問題 11） | 完了。`ngx_encode_base64()` で各クレームをエンコード |
| **`oidc_return_to` へのクエリ文字列保存**（問題 12） | 完了。`r->uri + '?' + r->args` を保存 |

### P2 — 機能完全性・運用品質（対応済み）

| 項目 | 状態 |
|------|------|
| **UserInfo エンドポイント対応** | 完了。`oidc_use_userinfo on` で有効化。Google/Microsoft 等の最小クレーム IdP に対応 |
| **任意クレームの変数展開 (`$oidc_claim_<name>`)** | 完了。JWT + UserInfo の全クレームに対応 |
| **継続リクエストでの任意クレーム** | 完了。セッション Cookie に extra_claims を格納・復元。継続アクセスでも `$oidc_claim_groups` 等が利用可能 |
| **E2E テストスイート** | 完了。Playwright + モック IdP による自動テスト |
| **"header already sent" バグ修正**（問題 14） | 完了。`redirect_issued` フラグで 302 後のコンテントフェーズへの落下を防止 |

### P2 残存 — 運用品質

| 項目 | 説明 |
|------|------|
| **RP-Initiated Logout** | シングルサインアウトの実現に必要。本番アプリではほぼ必須 |
| **SSL/TLS 設定 (`oidc_ssl_trusted_certificate`)** | 自己署名証明書・内部 CA 環境での信頼性確保 |

### P3 — 拡張・互換性

| 項目 | 説明 |
|------|------|
| **`$oidc_id_token` 変数** | ID トークンをそのままバックエンドに渡すユースケース向け |
| **`oidc_provider` ブロック構文** | 公式 NGINX Plus モジュールとの設定互換性 |
| **`extra_auth_args` ディレクティブ** | `login_hint`, `prompt=select_account` など特定ユースケース向け追加パラメータ |
| **`client_secret_post` 認証方式** | `client_secret_basic` を受け付けない IdP への対応 |

### P4 — 将来対応

| 項目 | 説明 |
|------|------|
| **Front-Channel Logout** | エンタープライズ向け。ユースケースが限定的 |
| **サーバーサイドセッション (keyval DB / Redis)** | スケールアウト時に有効。現状の HMAC Cookie でも動作は可能 |
| **Token Introspection** | IdP への失効確認。リアルタイム性が必要な場合に検討 |
| **リフレッシュトークン** | アクセストークンの自動更新 |
| **複数プロバイダ対応** | ロケーションごとに異なる IdP を設定 |

### 推奨実装順序

```
P0: PKCE + SSRF 対策強化  ← 完了
P1: access_token チェック緩和 / スコープ設定 / $oidc_access_token / ペイロードデリミタ修正 / return_to クエリ文字列  ← 完了
P2: 任意クレーム変数 ($oidc_claim_*) / UserInfo エンドポイント / 継続リクエストでの任意クレーム永続化 / E2E テスト / "header already sent" バグ修正  ← 完了
  ↓
P2 (残): RP-Initiated Logout → SSL設定
  ↓
P3: $oidc_id_token → oidc_providerブロック → extra_auth_args → client_secret_post
  ↓
P4: Front-Channel Logout → keyval DB → Token Introspection → リフレッシュトークン → 複数プロバイダ
```

P0+P1+P2 が完了しました。実際の IdP との接続・本番投入に必要な機能が揃っています。

---

## まとめ

Authorization Code Flow の基本的な実装は完成しており、非同期サブリクエストを使った NGINX らしいノンブロッキングアーキテクチャも適切に実装されています。

**現在の主要な実装内容**：

- `oidc_cookie_secret` ディレクティブと `init_process` フックにより、マルチワーカー環境での HMAC シークレット共有が実現
- セッション Cookie のペイロード `B64(sub):B64(email):B64(name):timestamp[|B64(key):B64(val)...]` により、固定クレームと任意クレームの両方を継続アクセスで復元
- PKCE（S256 メソッド）による認可コード横取り攻撃の防止
- `$oidc_discovery_url` / `$oidc_jwks_url` / `$oidc_userinfo_url` 変数による SSRF 対策
- `oidc_use_userinfo on` ディレクティブによる UserInfo エンドポイント統合
- `ctx->redirect_issued` フラグによる "header already sent" 問題の解決
- `ngx_http_oidc_issue_session_and_redirect` による Cookie 発行ロジックの集約
- Playwright + モック IdP による E2E テストスイート（`groups`・`tenant_id` 等の任意クレームの継続アクセス検証を含む）

**残存する課題**（P2 後半以降）：
- RP-Initiated Logout、SSL/TLS 設定 など

P0+P1+P2 が完了したことで、Google・Microsoft Azure AD など最小クレーム IdP も含めた本番環境への投入が実現可能なレベルに達しています。
