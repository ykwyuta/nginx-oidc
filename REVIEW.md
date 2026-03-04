# NGINX OIDC モジュール — ソースコードレビュー

## 概要

`ngx_http_oidc_module` は、NGINX Open Source に OpenID Connect (OIDC) 認証機能を追加する C 言語製のダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現することを目的とし、OAuth 2.0 Authorization Code Flow を実装します。

ソースは単一ファイル `ngx_http_oidc_module.c`（1167 行）にまとめられており、以下の外部ライブラリに依存します。

| ライブラリ | 用途 |
|------------|------|
| OpenSSL (libssl / libcrypto) | 乱数生成・HMAC-SHA256 |
| Jansson | JSON パース（ディスカバリ・トークンレスポンス） |
| libjwt (>= 1.15.3) | JWT デコード・署名検証 |

---

## ファイル構成

```
nginx-oidc/
├── ngx_http_oidc_module.c   # メインソース（1167 行）
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
    time_t discovery_expires;                      // キャッシュ有効期限（現在未使用）
    u_char hmac_secret[32];                        // セッションCookie署名用秘密鍵
    ngx_uint_t secret_initialized:1;               // 秘密鍵初期化済みフラグ
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

- **`ngx_http_oidc_main_conf_t`** はワーカープロセス起動時に確保され、プロバイダメタデータのキャッシュおよび HMAC 秘密鍵を保持します。
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
   |                        親リクエストを再開                        |
   |                             |                                    |
   |                        [access_handler 再実行]                   |
   |                        oidc_auth Cookie なし？                   |
   |                        → state / nonce を RAND_bytes で生成      |
   |<── 302 + Set-Cookie ────────|                                    |
   |   (oidc_state=HEX64, oidc_nonce=HEX64; HttpOnly)                |
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
   |                        HMAC-SHA256(sub:timestamp) で              |
   |                          oidc_auth Cookie を発行                 |
   |                        oidc_state / oidc_nonce Cookie を削除     |
   |<── 302 Location: / ─────────|                                    |
   |   Set-Cookie: oidc_auth=HMAC_HEX+PAYLOAD; HttpOnly; Path=/      |
   |                                                                  |
   |─── GET / ───────────────────>|                                   |
   |                        [access_handler]                          |
   |                        oidc_auth Cookie を取得                   |
   |                        HMAC-SHA256 で署名を検証                  |
   |                        sub を ctx->claims.sub に復元             |
   |                        → NGX_DECLINED（通過）                   |
   |<── 200 OK ──────────────────|                                    |
```

---

## 主要関数の解説

### `ngx_http_oidc_access_handler`（行 832–1043）

HTTP アクセスフェーズで呼び出されるメイン関数です。以下の順で判定します。

1. `auth_oidc` が無効、またはサブリクエスト自身 (`r != r->main`) → `NGX_DECLINED`（スキップ）
2. `mcf->metadata` が未取得かつ `discovery_attempted` が立っていない → ディスカバリ開始 (`NGX_AGAIN`)
3. `discovery_attempted` が立っているのにメタデータがない → 500 エラー（同一リクエスト内でのリトライ防止）
4. URI がコールバックパス (`redirect_uri`) に一致 → `state` 検証 → トークン取得開始
5. `oidc_auth` Cookie の HMAC 検証成功 → `NGX_DECLINED`（認証済みとして通過）
6. 上記以外（未認証） → IdP へ 302 リダイレクト

---

### `ngx_http_oidc_start_discovery` / `ngx_http_oidc_discovery_handler`（行 136–131）

NGINX のサブリクエスト機構を使い `/_oidc_discovery` 内部ロケーションへ非同期リクエストを送ります。`ngx_http_post_subrequest_t` にコールバック関数を登録し `NGX_AGAIN` を返すことで、イベントループをブロックせずにレスポンスを待ちます。

完了ハンドラ `ngx_http_oidc_discovery_handler` では Jansson の `json_loadb()` で JSON をパースし、3 つのエンドポイント URL を `mcf->metadata`（グローバルプール）へコピーします。成功後は `r->parent->write_event_handler = ngx_http_core_run_phases` で親リクエストのフェーズ処理を再開させます。

---

### `ngx_http_oidc_parse_discovery_json`（行 175–225）

`authorization_endpoint`・`token_endpoint`・`jwks_uri` の 3 フィールドを抽出します。各文字列は `ngx_cycle->pool`（ワーカー生存期間中有効なグローバルプール）に確保されるため、リクエスト終了後もメタデータが保持されます。

---

### `ngx_http_oidc_redirect_to_idp`（行 713–827）

`RAND_bytes()` で 32 バイトの乱数を 2 つ生成し、それぞれ 64 文字の HEX 文字列（`state`・`nonce`）に変換します。`client_id` と `redirect_uri` は `ngx_escape_uri()` でパーセントエンコードしたうえで認可エンドポイント URL に付加します。`oidc_state` と `oidc_nonce` を `HttpOnly` Cookie として発行し、302 レスポンスを返します。

---

### `ngx_http_oidc_start_token_request` / `ngx_http_oidc_token_handler`（行 633–381）

トークンエンドポイントへの POST を模倣するため、`code`・`client_id`・`client_secret`・`redirect_uri`・`grant_type` をクエリストリング形式で組み立て、`/_oidc_token` 内部ロケーションへサブリクエストを発行します（nginx.conf 側で POST ボディに変換）。

完了ハンドラ `ngx_http_oidc_token_handler` では JSON から `id_token` を取り出して `ctx->id_token` に保存し、引き続き JWKS 取得サブリクエストを連鎖させます。

---

### `ngx_http_oidc_start_jwks_request` / `ngx_http_oidc_jwks_handler`（行 388–628）

`/_oidc_jwks` 内部ロケーション経由で `jwks_uri` から JWKS JSON を取得し、libjwt の `jwt_decode()` に渡します。この関数は JWT の署名をインラインで検証します。検証成功後は以下の順で処理します。

1. `exp` クレームで有効期限を確認（`ngx_time()` との比較）
2. `oidc_nonce` Cookie と JWT の `nonce` クレームを比較してリプレイ攻撃を防止
3. `sub`・`email`・`name` を `ctx->claims` に保存
4. `HMAC(EVP_sha256(), hmac_secret, payload)` で署名し `oidc_auth` Cookie を発行
5. `oidc_state`・`oidc_nonce` Cookie を過去の日付で上書きして削除
6. `Location: /` で 302 リダイレクト

---

### セッション Cookie の検証（行 1001–1033）

`oidc_auth` Cookie の形式は `HMAC_HEX(64文字) + PAYLOAD` です。アクセスハンドラはペイロード部分に対して同じ HMAC を計算し、Cookie 先頭 64 文字と一致するか確認します。一致すれば `sub` を `:` 区切りで取り出して `ctx->claims.sub` に格納します。

---

## nginx.conf 設定例

```nginx
load_module modules/ngx_http_oidc_module.so;

http {
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

> **注意**: 認証済みセッション（`oidc_auth` Cookie による継続認証）では `sub` のみが Cookie から復元されます。`email` と `name` はセッション Cookie に含まれていないため、継続リクエストでは空になります（後述の改善点 3 参照）。

---

## 改善点

### 🔴 重大なバグ

#### 1. HMAC シークレットがマルチワーカー環境で共有されない

**該当箇所**: `ngx_http_oidc_main_conf_t.hmac_secret`（行 33）、Cookie 発行（行 539–543）、Cookie 検証（行 1003–1007）

`hmac_secret` は `ngx_http_oidc_main_conf_t` に格納されており、各ワーカープロセスが独立して `RAND_bytes()` で初期化します。NGINX はデフォルトで複数のワーカープロセスを持つため、**ワーカー A が発行したセッション Cookie はワーカー B では検証できず、ユーザーは断続的に再認証を強いられます**。

```c
// 各ワーカーが独自のシークレットを生成してしまう
if (!mcf->secret_initialized) {
    if (RAND_bytes(mcf->hmac_secret, sizeof(mcf->hmac_secret)) == 1) {
        mcf->secret_initialized = 1;
    }
}
```

**改善策**: `nginx.conf` に `oidc_cookie_secret` ディレクティブを追加してシークレットを外部から注入するか、NGINX の共有メモリ (`ngx_shmem`) を使ってワーカー間でシークレットを共有する。プロセス起動時フック (`init_process`) でシークレットを一度だけ初期化するのが望ましい。

---

#### 2. Cookie 検証中にシークレットを再生成してしまう

**該当箇所**: 行 1003–1007

Cookie 発行時（行 539–543）と検証時（行 1003–1007）の両方で、`secret_initialized` フラグが未設定なら `RAND_bytes()` によるシークレット初期化が走ります。ワーカープロセスが再起動すると、Cookie 発行時とは異なるシークレットが生成されて HMAC 検証が常に失敗し、**全ユーザーが強制ログアウト**されます。

---

#### 3. セッション Cookie に email と name が含まれない

**該当箇所**: Cookie 発行（行 550–553）、Cookie 検証（行 1022–1030）

発行時のペイロードは `sub:timestamp` のみです。継続アクセス時は `oidc_claim_email` と `oidc_claim_name` が常に空になり、バックエンドアプリケーションへのヘッダ転送が機能しません。

```c
// 現状：sub と timestamp のみ
payload.len = ngx_snprintf(payload.data, payload.len, "%V:%T",
                           &ctx->claims.sub, ngx_time()) - payload.data;
```

**改善策**: ペイロードに `email` と `name` を含める（例: `sub:email:name:timestamp`）か、サーバーサイドのセッションストア（Redis 等）を使用する。

---

### 🟠 設計上の問題

#### 4. 認証後のリダイレクト先が常に `/` に固定

**該当箇所**: 行 606

```c
ngx_str_set(&location->value, "/");
```

ユーザーが `/admin/settings` にアクセスして認証フローに入った場合でも、認証後は必ず `/` にリダイレクトされます。

**改善策**: IdP へリダイレクトする際に元のリクエスト URI を URL エンコードして `state` パラメータや専用 Cookie (`oidc_return_to`) に保存し、コールバック後に復元する。

---

#### 5. Cookie パース処理が複数箇所に重複

同一の Cookie 走査コードが 3 箇所に分散しています。

| 箇所 | 対象 Cookie |
|------|-------------|
| `ngx_http_oidc_jwks_handler` 行 476–505 | `oidc_nonce` |
| `ngx_http_oidc_access_handler` 行 921–946 | `oidc_state` |
| `ngx_http_oidc_access_handler` 行 967–999 | `oidc_auth` |

**改善策**: 以下のようなヘルパー関数に集約して重複を排除する。

```c
static ngx_int_t ngx_http_oidc_get_cookie(ngx_http_request_t *r,
    const char *name, size_t name_len, ngx_str_t *value);
```

---

#### 6. ディスカバリキャッシュの有効期限が機能していない

**該当箇所**: `ngx_http_oidc_main_conf_t.discovery_expires`（行 32）

フィールドは定義されているものの、値がセット・参照されることはなく常に `0` です。メタデータは一度取得されると永続的にキャッシュされ続けるため、IdP が JWK を鍵ローテーションしても自動更新されません。

**改善策**: ディスカバリ成功時に `mcf->discovery_expires = ngx_time() + 3600;` を設定し、アクセスハンドラで期限切れを確認してメタデータを再取得する。

---

#### 7. `/_oidc_discovery` の `proxy_pass $arg_url` が SSRF リスクを持つ

nginx.conf の設計例として `proxy_pass $arg_url;` を使う構成が想定されています。内部ロケーション (`internal`) なので外部からは直接悪用しにくいですが、もしモジュールに URL 注入の脆弱性があれば任意の内部エンドポイントへリクエストが飛ぶ可能性があります。

**改善策**: モジュール側でプロバイダ URL を設定値から組み立てたうえで、内部ロケーションには `$oidc_discovery_url` のような専用 NGINX 変数を使い、値の出所を制限する。

---

### 🟡 セキュリティ上の改善点

#### 8. Cookie に `Secure` 属性がない

**該当箇所**: 行 575, 807, 823, 589, 596

すべての Cookie（`oidc_auth`・`oidc_state`・`oidc_nonce`）に `Secure` 属性がなく、HTTP 通信でも送受信されます。本番 HTTPS 環境では必須です。

```c
// 現状
"; HttpOnly; Path=/"
// 改善後
"; HttpOnly; Secure; SameSite=Lax; Path=/"
```

#### 9. Cookie に `SameSite` 属性がない

`SameSite=Lax` がないと、クロスサイトリクエストで Cookie が意図せず送信される可能性があります。`state` によるCSRF防止を補完する意味でも設定すべきです。

#### 10. HMAC 比較がタイミング攻撃に脆弱

**該当箇所**: 行 1019

```c
if (ngx_strncmp(auth_cookie.data, expected_mac_hex, 64) == 0) {
```

`ngx_strncmp` は最初の不一致で即座に返るため、応答時間の差を観測してHMACを推測するタイミング攻撃に対して脆弱です。

**改善策**: OpenSSL の `CRYPTO_memcmp()` を使用する（常に全バイトを比較）。

```c
if (CRYPTO_memcmp(auth_cookie.data, expected_mac_hex, 64) == 0) {
```

---

### 🟢 未実装の機能

| 機能 | 説明 |
|------|------|
| RP-Initiated Logout | IdP の `/logout` エンドポイントへのリダイレクト |
| リフレッシュトークン | アクセストークンの自動更新 |
| UserInfo エンドポイント | プロフィール情報の追加取得 |
| Token Introspection | IdP への失効確認 |
| 元リクエスト URL の保存 | 認証後に元 URL に戻す |
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
| Phase 5 | テスト・最適化・HMAC 秘密鍵の共有メモリ化 | ❌ 未着手 |

---

## まとめ

Authorization Code Flow の基本的な実装は完成しており、非同期サブリクエストを使った NGINX らしいノンブロッキングアーキテクチャも適切に実装されています。Phase 4 の JWT 署名検証・nonce 検証・HMAC セッション Cookie も動作しています。

ただし **HMAC シークレットのマルチプロセス問題**（改善点 1・2）は本番環境では致命的なバグであり、マルチワーカー構成では常に認証が不安定になります。また認証後のリダイレクト先の固定（改善点 4）、セッション Cookie の情報不足（改善点 3）、タイミング攻撃への対策（改善点 10）も実用化に向けて早急に対応すべき課題です。
