# NGINX OIDC モジュール — ソースコードレビュー

## 概要

`ngx_http_oidc_module` は、NGINX Open Source に OpenID Connect (OIDC) 認証機能を追加する C 言語製のダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現することを目的とし、OAuth 2.0 Authorization Code Flow を実装します。

ソースは単一ファイル `ngx_http_oidc_module.c`（1286 行）にまとめられており、以下の外部ライブラリに依存します。

| ライブラリ | 用途 |
|------------|------|
| OpenSSL (libssl / libcrypto) | 乱数生成・HMAC-SHA256・定時間比較 |
| Jansson | JSON パース（ディスカバリ・トークンレスポンス） |
| libjwt (>= 1.15.3) | JWT デコード・署名検証 |

---

## ファイル構成

```
nginx-oidc/
├── ngx_http_oidc_module.c   # メインソース（1286 行）
├── config                   # NGINX モジュールビルド設定
├── README.md                # 要件定義
├── TASK.md                  # 開発フェーズチェックリスト
├── TEST.md                  # テスト手順・ビルド手順
└── REVIEW.md                # 本ファイル
```

---

## データ構造

```c
// OIDCプロバイダのエンドポイント情報（Discoveryから取得）
typedef struct {
    ngx_str_t authorization_endpoint;  // 認可エンドポイントURL
    ngx_str_t token_endpoint;          // トークンエンドポイントURL
    ngx_str_t jwks_uri;                // JWKSエンドポイントURL
} ngx_http_oidc_provider_metadata_t;

// IDトークンから抽出したクレーム
typedef struct {
    ngx_str_t sub;    // ユーザー識別子
    ngx_str_t email;  // メールアドレス
    ngx_str_t name;   // 表示名
} ngx_http_oidc_claims_t;

// グローバル設定（ワーカープロセス内でキャッシュ）
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  // プロバイダメタデータ
    time_t discovery_expires;                      // キャッシュ有効期限（TTL: 3600秒）
    u_char hmac_secret[32];                        // セッションCookie署名用秘密鍵
    ngx_uint_t secret_initialized:1;               // 秘密鍵初期化済みフラグ
    ngx_str_t cookie_secret;                       // oidc_cookie_secret ディレクティブで設定した共有シークレット
} ngx_http_oidc_main_conf_t;

// ロケーション設定（nginx.conf から読み込み）
typedef struct {
    ngx_flag_t  auth_oidc;      // OIDC認証の有効/無効
    ngx_str_t   oidc_provider;  // プロバイダのベースURL
    ngx_str_t   client_id;      // OAuthクライアントID
    ngx_str_t   client_secret;  // OAuthクライアントシークレット
    ngx_str_t   redirect_uri;   // コールバックURI
} ngx_http_oidc_loc_conf_t;

// リクエストコンテキスト（リクエスト単位で保持）
typedef struct {
    ngx_http_oidc_provider_metadata_t *metadata;  // メタデータへのポインタ
    ngx_uint_t discovery_attempted:1;              // ディスカバリ試行済みフラグ
    ngx_uint_t token_attempted:1;                  // トークン取得試行済みフラグ
    ngx_str_t id_token;                            // 取得したIDトークン文字列
    ngx_http_oidc_claims_t claims;                 // 検証済みクレーム
} ngx_http_oidc_ctx_t;
```

- **`ngx_http_oidc_main_conf_t`** はワーカープロセス起動時に確保され、プロバイダメタデータのキャッシュおよび HMAC 秘密鍵を保持します。`cookie_secret` は `oidc_cookie_secret` ディレクティブで設定した生の文字列を保持し、`init_process` フックで `hmac_secret` に転写されます。
- **`ngx_http_oidc_loc_conf_t`** は設定ファイル読み込み時に確定し、ロケーションごとの OIDC 設定を保持します。
- **`ngx_http_oidc_ctx_t`** はリクエストプールに確保され、リクエストが終わると解放されます。

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
   |                        → state / nonce を RAND_bytes で生成      |
   |                        → 元リクエスト URI を oidc_return_to Cookie に保存
   |<── 302 + Set-Cookie ────────|                                    |
   |   (oidc_state=HEX64; HttpOnly; Secure; SameSite=Lax)            |
   |   (oidc_nonce=HEX64; HttpOnly; Secure; SameSite=Lax)            |
   |   (oidc_return_to=/protected; HttpOnly; Secure; SameSite=Lax)   |
   |                                                                  |
   |─── GET /authorize ──────────────────────────────────────────────>|
   |   ?response_type=code&scope=openid&client_id=...                 |
   |   &redirect_uri=...&state=HEX64&nonce=HEX64                     |
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
   |                        sub / email / name を ctx に保存         |
   |                        HMAC-SHA256(sub:email:name:timestamp) で  |
   |                          oidc_auth Cookie を発行                 |
   |                        oidc_state / oidc_nonce / oidc_return_to Cookie を削除
   |<── 302 Location: /protected ─|                                   |
   |   Set-Cookie: oidc_auth=HMAC_HEX+PAYLOAD; HttpOnly; Secure; SameSite=Lax; Path=/
   |                                                                  |
   |─── GET /protected ──────────>|                                   |
   |                        [access_handler]                          |
   |                        oidc_auth Cookie を取得                   |
   |                        CRYPTO_memcmp() で HMAC 署名を検証        |
   |                        sub / email / name を ctx->claims に復元  |
   |                        → NGX_DECLINED（通過）                   |
   |<── 200 OK ──────────────────|                                    |
```

---

## 主要関数の解説

### `ngx_http_oidc_get_cookie`（行 71–131）

Cookie ヘッダを走査して指定名の Cookie 値を返す共通ヘルパー関数です。以前は Cookie の検索ロジックが 3 箇所に重複していましたが、この関数に集約されています。`name=` プレフィックスで前方一致検索を行い、`;` で区切られた Cookie の値を `ngx_str_t` に格納して返します。

---

### `ngx_http_oidc_access_handler`（行 946–1118）

HTTP アクセスフェーズで呼び出されるメイン関数です。以下の順で判定します。

1. `auth_oidc` が無効、またはサブリクエスト自身 (`r != r->main`) → `NGX_DECLINED`（スキップ）
2. `mcf->discovery_expires` が期限切れ → メタデータを破棄して再取得フローへ
3. `mcf->metadata` が未取得かつ `discovery_attempted` が立っていない → ディスカバリ開始 (`NGX_AGAIN`)
4. `discovery_attempted` が立っているのにメタデータがない → 500 エラー（同一リクエスト内でのリトライ防止）
5. URI がコールバックパス (`redirect_uri`) に一致 → `state` 検証 → トークン取得開始
6. `oidc_auth` Cookie の HMAC 検証成功 → `NGX_DECLINED`（認証済みとして通過）
7. 上記以外（未認証） → `oidc_return_to` Cookie に元 URI を保存して IdP へ 302 リダイレクト

---

### `ngx_http_oidc_start_discovery` / `ngx_http_oidc_discovery_handler`（行 136–239）

NGINX のサブリクエスト機構を使い `/_oidc_discovery` 内部ロケーションへ非同期リクエストを送ります。`ngx_http_post_subrequest_t` にコールバック関数を登録し `NGX_AGAIN` を返すことで、イベントループをブロックせずにレスポンスを待ちます。

完了ハンドラ `ngx_http_oidc_discovery_handler` では Jansson の `json_loadb()` で JSON をパースし、3 つのエンドポイント URL を `mcf->metadata`（グローバルプール）へコピーします。成功後は `mcf->discovery_expires = ngx_time() + 3600` でキャッシュ TTL を設定し、`r->parent->write_event_handler = ngx_http_core_run_phases` で親リクエストのフェーズ処理を再開させます。

---

### `ngx_http_oidc_parse_discovery_json`（行 244–294）

`authorization_endpoint`・`token_endpoint`・`jwks_uri` の 3 フィールドを抽出します。各文字列は `ngx_cycle->pool`（ワーカー生存期間中有効なグローバルプール）に確保されるため、リクエスト終了後もメタデータが保持されます。

---

### `ngx_http_oidc_redirect_to_idp`（行 801–941）

`RAND_bytes()` で 32 バイトの乱数を 2 つ生成し、それぞれ 64 文字の HEX 文字列（`state`・`nonce`）に変換します。`client_id` と `redirect_uri` は `ngx_escape_uri()` でパーセントエンコードしたうえで認可エンドポイント URL に付加します。

以下の 3 つの Cookie を発行して 302 レスポンスを返します（すべて `HttpOnly; Secure; SameSite=Lax; Path=/`）。

| Cookie 名 | 内容 |
|-----------|------|
| `oidc_state` | CSRF 防止用の state 値 (64文字 HEX) |
| `oidc_nonce` | リプレイ攻撃防止用の nonce 値 (64文字 HEX) |
| `oidc_return_to` | 認証後のリダイレクト先 URI（最大 2048 バイト） |

---

### `ngx_http_oidc_start_token_request` / `ngx_http_oidc_token_handler`（行 391–796）

トークンエンドポイントへの POST を模倣するため、`code`・`client_id`・`client_secret`・`redirect_uri`・`grant_type` をクエリストリング形式で組み立て、`/_oidc_token` 内部ロケーションへサブリクエストを発行します（nginx.conf 側で POST ボディに変換）。

完了ハンドラ `ngx_http_oidc_token_handler` では JSON から `id_token` と `access_token` の両方を確認します。`id_token` を `ctx->id_token` に保存し、引き続き JWKS 取得サブリクエストを連鎖させます。

---

### `ngx_http_oidc_start_jwks_request` / `ngx_http_oidc_jwks_handler`（行 467–716）

`/_oidc_jwks` 内部ロケーション経由で `jwks_uri` から JWKS JSON を取得し、libjwt の `jwt_decode()` に渡します。この関数は JWT の署名をインラインで検証します。検証成功後は以下の順で処理します。

1. `exp` クレームで有効期限を確認（`ngx_time()` との比較）
2. `oidc_nonce` Cookie と JWT の `nonce` クレームを比較してリプレイ攻撃を防止
3. `sub`・`email`・`name` を `ctx->claims` に保存
4. `HMAC(EVP_sha256(), hmac_secret, payload)` で署名し `oidc_auth` Cookie を発行（ペイロード形式: `sub:email:name:timestamp`）
5. `oidc_state`・`oidc_nonce`・`oidc_return_to` Cookie を過去の日付で上書きして削除
6. `oidc_return_to` Cookie の値（元リクエスト URI）に 302 リダイレクト

---

### セッション Cookie の検証（行 1051–1108）

`oidc_auth` Cookie の形式は `HMAC_HEX(64文字) + PAYLOAD` です。アクセスハンドラはペイロード部分に対して同じ HMAC を計算し、`CRYPTO_memcmp()` で定時間比較を行います。Cookie 先頭 64 文字と一致すれば、ペイロード（`sub:email:name:timestamp`）を `:` 区切りで分解して `ctx->claims` に格納します。これにより継続アクセスでも `$oidc_claim_sub`・`$oidc_claim_email`・`$oidc_claim_name` の 3 変数がすべて利用可能です。

---

### `ngx_http_oidc_init_process`（行 1170–1203）

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

        # Discovery サブリクエスト用（動的 proxy_pass）
        location = /_oidc_discovery {
            internal;
            proxy_pass $arg_url;
        }

        # Token エンドポイント用（POST ボディに変換）
        location = /_oidc_token {
            internal;
            proxy_pass http://idp.example.com/realms/myrealm/protocol/openid-connect/token;
            proxy_method POST;
            proxy_set_header Content-Type "application/x-www-form-urlencoded";
            proxy_set_body $args;
        }

        # JWKS サブリクエスト用（動的 proxy_pass）
        location = /_oidc_jwks {
            internal;
            proxy_pass $arg_url;
        }

        # 保護するロケーション
        location / {
            auth_oidc         on;
            oidc_provider     "https://idp.example.com/realms/myrealm";
            oidc_client_id    "my-client";
            oidc_client_secret "secret";
            oidc_redirect_uri "/callback";

            proxy_pass http://backend;
            proxy_set_header X-Remote-User  $oidc_claim_sub;
            proxy_set_header X-Remote-Email $oidc_claim_email;
            proxy_set_header X-Remote-Name  $oidc_claim_name;
        }
    }
}
```

---

## 公開 NGINX 変数

| 変数名 | 内容 |
|--------|------|
| `$oidc_claim_sub` | JWT の `sub` クレーム（ユーザーID） |
| `$oidc_claim_email` | JWT の `email` クレーム |
| `$oidc_claim_name` | JWT の `name` クレーム |

継続認証（`oidc_auth` Cookie による再訪問）でも、セッション Cookie のペイロードに `sub:email:name:timestamp` を含めているため、3 つの変数すべてが正しく復元されます。

---

## 改善点

### ✅ 解決済みの問題

以下の問題は現在の実装で対処済みです。

| 番号 | 問題 | 対処内容 |
|------|------|---------|
| 1 | HMAC シークレットがマルチワーカー環境で共有されない | `oidc_cookie_secret` ディレクティブ追加。`init_process` フックで全ワーカーに同一シークレットを配布 |
| 2 | Cookie 検証中にシークレットを再生成してしまう | `init_process` フックで起動時に一度だけ初期化。Cookie 発行・検証時は再生成しない |
| 3 | セッション Cookie に email と name が含まれない | ペイロードを `sub:email:name:timestamp` 形式に変更。継続アクセスで 3 変数すべて復元可能 |
| 4 | 認証後のリダイレクト先が常に `/` に固定 | `oidc_return_to` Cookie に元リクエスト URI を保存し、認証後に復元 |
| 5 | Cookie パース処理が複数箇所に重複 | `ngx_http_oidc_get_cookie()` ヘルパー関数に集約 |
| 6 | ディスカバリキャッシュの有効期限が機能していない | `discovery_expires = ngx_time() + 3600` を設定。アクセスハンドラで TTL チェックして期限切れ時に再取得 |
| 8 | Cookie に `Secure` 属性がない | すべての Cookie に `; HttpOnly; Secure; SameSite=Lax; Path=/` を付加 |
| 9 | Cookie に `SameSite` 属性がない | 同上 |
| 10 | HMAC 比較がタイミング攻撃に脆弱 | `ngx_strncmp()` を `CRYPTO_memcmp()` に置き換え |

---

### 🔴 未解決の重大な問題

#### 7. `/_oidc_discovery` と `/_oidc_jwks` の `proxy_pass $arg_url` が SSRF リスクを持つ

**該当箇所**: nginx.conf 設計例の `/_oidc_discovery` および `/_oidc_jwks` ロケーション

```nginx
location = /_oidc_discovery {
    internal;
    proxy_pass $arg_url;
}
```

内部ロケーション (`internal`) なので外部から直接悪用はできませんが、モジュール側に URL 注入の脆弱性があれば任意の内部エンドポイントへリクエストが届く可能性があります。

**改善策**: モジュール側でプロバイダ URL を設定値から組み立てたうえで、専用の NGINX 変数（例: `$oidc_discovery_url`）を介して内部ロケーションに渡す。これにより URL の出所を設定値に限定できます。

---

### 🟠 新規に発見された問題

#### 11. セッション Cookie ペイロードのデリミタ問題

**該当箇所**: Cookie 発行（行 609–614）、Cookie 検証（行 1080–1104）

ペイロードの区切り文字として `:` を使用しているため、`name` クレームに `:` が含まれる場合（例: `"John: Smith"` や `"Dr. Smith: MD"`）にペイロードの解析が壊れます。

```c
// 発行時のペイロード: sub:email:name:timestamp
// name に ':' が含まれると timestamp の位置がずれる
payload.len = ngx_snprintf(payload.data, payload.len,
                           "%V:%V:%V:%T",
                           &ctx->claims.sub, &ctx->claims.email,
                           &ctx->claims.name, ngx_time()) - payload.data;
```

検証時の解析は `ngx_strlchr()` で順方向に `:` を探すため、`name` 中の `:` を timestamp の区切りと誤認識します。

**改善策**: 各フィールドを Base64URL エンコードしてから `:` で連結する、またはペイロード全体を JSON にエンコードする。

---

#### 12. `oidc_return_to` Cookie にクエリ文字列が含まれない

**該当箇所**: Cookie 発行（行 925–934）

```c
// r->uri はパス部分のみ。クエリ文字列 (r->args) は含まれない
p = ngx_cpymem(p, r->uri.data, uri_len);
```

ユーザーが `/search?q=nginx` にアクセスして認証フローに入った場合、認証後は `/search` にリダイレクトされ、クエリ文字列が失われます。

**改善策**: クエリ文字列が存在する場合は `r->uri` + `?` + `r->args` を連結して保存する。ただし Cookie サイズ制限（通常 4096 バイト）に注意が必要です。

---

#### 13. `access_token` の存在チェックが IdP 互換性を損なう

**該当箇所**: `ngx_http_oidc_token_handler`（行 432）

```c
if (json_is_string(id_token) && json_is_string(access_token)) {
```

OIDC の Authorization Code Flow では `id_token` と `access_token` の両方がトークンレスポンスに含まれることが仕様上期待されますが、一部の IdP 設定やクライアント設定によっては `access_token` が省略される場合があります。現状の実装では `access_token` が存在しないと認証フローが完了しません。

**改善策**: `id_token` の存在のみを必須チェックとし、`access_token` はオプションとして扱う。将来的に `$oidc_access_token` 変数を実装する際に格納処理を追加する。

---

### 🟡 セキュリティ上の改善点（未実装）

#### P0: PKCE（Proof Key for Code Exchange）

OAuth 2.1 で必須。Authorization Code Interception 攻撃への対策。現代の IdP（Keycloak, Auth0 等）は PKCE を要求するケースが増加中。`code_verifier` を `RAND_bytes()` で生成し、`code_challenge` として認可リクエストに含め、トークンリクエスト時に `code_verifier` を送信する必要があります。

---

### 🟢 未実装の機能

| 機能 | 説明 |
|------|------|
| PKCE | OAuth 2.1 で必須。code_verifier / code_challenge を実装する |
| スコープ設定 (`oidc_scope`) | `email`, `profile` など `openid` 以外のスコープの設定 |
| `$oidc_access_token` 変数 | `proxy_set_header Authorization "Bearer $oidc_access_token"` への対応 |
| RP-Initiated Logout | IdP の `/logout` エンドポイントへのリダイレクト |
| リフレッシュトークン | アクセストークンの自動更新 |
| UserInfo エンドポイント | プロフィール情報の追加取得 |
| Token Introspection | IdP への失効確認 |
| 複数プロバイダ対応 | ロケーションごとに異なる IdP を設定 |
| 自動テストスイート | 統合テストの自動化 |

---

## 実装フェーズの現状

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | ✅ 完了 |
| Phase 2 | OIDC Discovery（非同期サブリクエスト） | ✅ 完了 |
| Phase 3 | 認証フロー・トークン交換・state 検証 | ✅ 完了 |
| Phase 4 | JWT 署名検証・nonce 検証・セッション Cookie 発行 | ✅ 完了 |
| Phase 5 | テスト・最適化・HMAC 秘密鍵の共有メモリ化 | 🔶 部分完了（`oidc_cookie_secret` による共有シークレット実装済み。自動テストは未着手） |

---

## 対応優先度

既存バグの修正・未実装機能の追加について、セキュリティ影響度・実用デプロイでの必要性・実装コストを軸に優先度を設定します。

### P0 — セキュリティ上必須（今すぐ対応）

| 項目 | 説明 |
|------|------|
| **PKCE 実装** | OAuth 2.1 で必須。Authorization Code Interception 攻撃への対策。現代の IdP（Keycloak, Auth0 等）は PKCE を要求するケースが増加中 |
| **SSRF 対策強化**（問題 7） | `proxy_pass $arg_url` を専用 NGINX 変数に限定。モジュールコードの URL 注入脆弱性と組み合わさるとリスクが高い |

### P1 — 実用デプロイに不可欠

| 項目 | 説明 |
|------|------|
| **`access_token` チェックの緩和**（問題 13） | `id_token` のみを必須とし、IdP 互換性を向上させる |
| **スコープ設定ディレクティブ (`oidc_scope`)** | `email`, `profile` など `openid` 以外のスコープはほぼ全ての実運用で必要 |
| **`$oidc_access_token` 変数** | `proxy_set_header Authorization "Bearer $oidc_access_token"` は最も一般的なユースケース |
| **Cookie ペイロードのデリミタ問題修正**（問題 11） | `name` クレームに `:` が含まれるユーザーで認証が壊れる |
| **`oidc_return_to` へのクエリ文字列保存**（問題 12） | クエリ文字列を保存することで認証後の UX が向上する |

### P2 — 機能完全性・運用品質

| 項目 | 説明 |
|------|------|
| **UserInfo エンドポイント対応** | Google, Microsoft 等は ID トークンのクレームを最小限にし UserInfo からの取得を前提とする |
| **RP-Initiated Logout** | シングルサインアウトの実現に必要。本番アプリではほぼ必須 |
| **SSL/TLS 設定 (`oidc_ssl_trusted_certificate`)** | 自己署名証明書・内部 CA 環境での信頼性確保 |
| **任意クレームの変数展開 (`$oidc_claim_<name>`)** | `groups`, `roles`, `tenant_id` など IdP ごとに異なるクレームへの対応 |

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
| **複数プロバイダ対応** | ロケーションごとに異なる IdP を設定 |
| **自動テストスイート** | 統合テストの自動化 |

### 推奨実装順序

```
P0: PKCE + SSRF 対策強化
  ↓
P1: access_token チェック緩和 → スコープ設定 → $oidc_access_token → ペイロードデリミタ修正 → return_to クエリ文字列対応
  ↓
P2: UserInfo → RP-Initiated Logout → SSL設定 → 任意クレーム変数
  ↓
P3: $oidc_id_token → oidc_providerブロック → extra_auth_args → client_secret_post
  ↓
P4: Front-Channel Logout → keyval DB → Token Introspection → 複数プロバイダ → テスト自動化
```

P0+P1 を揃えることで、実際の IdP との接続に使える最低限の実用レベルに到達します。

---

## まとめ

Authorization Code Flow の基本的な実装は完成しており、非同期サブリクエストを使った NGINX らしいノンブロッキングアーキテクチャも適切に実装されています。前回のレビュー以降、多数の問題が解決されています。

**解決済みの主な改善**：
- `oidc_cookie_secret` ディレクティブと `init_process` フックの追加により、マルチワーカー環境での HMAC シークレット共有が実現（ただし未設定時は警告ログを出力しつつランダムシークレットで動作）
- セッション Cookie のペイロードを `sub:email:name:timestamp` に拡張し、継続アクセスでも `$oidc_claim_email` / `$oidc_claim_name` が正しく利用可能に
- `oidc_return_to` Cookie による元リクエスト URI の保存と認証後の復元
- `ngx_http_oidc_get_cookie()` ヘルパーによる Cookie パースロジックの統一
- ディスカバリキャッシュ TTL（3600 秒）の実装
- すべての Cookie への `Secure; SameSite=Lax` 属性付加
- `CRYPTO_memcmp()` によるタイミング攻撃対策

**残存する主な課題**：
- **PKCE 未実装**（P0）: 現代の IdP との互換性・セキュリティ上の必須要件
- **Cookie ペイロードのデリミタ問題**（P1）: `name` クレームに `:` が含まれると解析が壊れる
- **SSRF リスク**（P0）: `proxy_pass $arg_url` を使う nginx.conf 設計の改善が必要
- **`access_token` 必須チェック**（P1）: 一部 IdP との互換性問題

優先度の観点からは、**P0 の PKCE 実装と SSRF 対策を最初に完了させ**、次に **P1 の実用機能と互換性修正を揃える**ことで、本番環境への投入が現実的になります。
