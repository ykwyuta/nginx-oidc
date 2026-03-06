# nginx-oidc

NGINX Open Source 向けの OpenID Connect (OIDC) 認証ダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現します。OAuth 2.0 Authorization Code Flow（PKCE 対応）を実装し、NGINX を Relying Party (RP) として動作させ、外部の Identity Provider (IdP) と連携したシングルサインオン (SSO) を提供します。

## 機能

- **Authorization Code Flow + PKCE (S256)**: セキュアな認証フローを実装
- **OIDC Discovery**: `/.well-known/openid-configuration` からエンドポイントを自動取得（TTL: 3600秒キャッシュ）
- **JWT 署名検証**: libjwt によるIDトークンの署名検証・有効期限・nonceチェック
- **セッション管理**: HMAC-SHA256 署名付き Cookie によるステートレスセッション
- **クレーム変数**: `$oidc_claim_sub`, `$oidc_claim_email`, `$oidc_claim_name` および `$oidc_claim_<任意名>` 変数
- **UserInfo エンドポイント**: `oidc_use_userinfo on` で追加クレームを取得
- **任意クレームの永続化**: セッション Cookie に任意クレームを格納し継続アクセスでも復元
- **SSRF 対策**: `$oidc_discovery_url` / `$oidc_jwks_url` / `$oidc_userinfo_url` 変数による URL の固定
- **マルチワーカー対応**: `oidc_cookie_secret` ディレクティブで全ワーカー間の HMAC シークレットを統一
- **タイミング攻撃対策**: `CRYPTO_memcmp()` による定時間 Cookie 検証

## 依存ライブラリ

| ライブラリ | バージョン | 用途 |
|------------|-----------|------|
| OpenSSL (libssl / libcrypto) | 任意 | PKCE / HMAC-SHA256 / 乱数生成 / 定時間比較 |
| Jansson | 任意 | Discovery・トークンレスポンスの JSON パース |
| libjwt | >= 1.15.3 | IDトークンのデコード・署名検証 |

## ビルド

```bash
# NGINX ソースと同じディレクトリで
./configure --add-dynamic-module=/path/to/nginx-oidc
make modules

# モジュールのコピー
cp objs/ngx_http_oidc_module.so /etc/nginx/modules/
```

ビルドに必要なパッケージ（Debian/Ubuntu の例）:

```bash
apt-get install libssl-dev libjansson-dev libjwt-dev
```

## 設定

### nginx.conf 設定例

```nginx
load_module modules/ngx_http_oidc_module.so;

http {
    # マルチワーカー構成では必須。全ワーカーで同一の HMAC シークレットを使用する。
    # openssl rand -hex 32 で生成した値を設定すること。
    oidc_cookie_secret "your-random-secret-here";

    server {
        listen 443 ssl;

        # Discovery サブリクエスト用（SSRF 対策: $oidc_discovery_url 変数を使用）
        location = /_oidc_discovery {
            internal;
            proxy_pass $oidc_discovery_url;
        }

        # Token エンドポイント用（クエリパラメータを POST ボディに変換）
        location = /_oidc_token {
            internal;
            proxy_pass https://idp.example.com/realms/myrealm/protocol/openid-connect/token;
            proxy_method POST;
            proxy_set_header Content-Type "application/x-www-form-urlencoded";
            proxy_set_body $args;
            proxy_set_header Content-Length "";
        }

        # JWKS サブリクエスト用（SSRF 対策: $oidc_jwks_url 変数を使用）
        location = /_oidc_jwks {
            internal;
            proxy_pass $oidc_jwks_url;
        }

        # UserInfo サブリクエスト用（oidc_use_userinfo on; が必要）
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
            oidc_scope         "openid profile email";
            # oidc_use_userinfo on;   # UserInfoエンドポイントから追加クレームを取得する場合

            proxy_pass http://backend;
            proxy_set_header X-Remote-User   $oidc_claim_sub;
            proxy_set_header X-Remote-Email  $oidc_claim_email;
            proxy_set_header X-Remote-Name   $oidc_claim_name;
            proxy_set_header X-Remote-Groups $oidc_claim_groups;
            # アクセストークンをバックエンドに渡す場合:
            # proxy_set_header Authorization "Bearer $oidc_access_token";
        }
    }
}
```

### ディレクティブ一覧

| ディレクティブ | コンテキスト | デフォルト | 説明 |
|--------------|------------|-----------|------|
| `auth_oidc on\|off` | location | off | OIDC 認証の有効/無効 |
| `oidc_provider <url>` | location | — | IdP のベース URL（Discovery に使用） |
| `oidc_client_id <id>` | location | — | OAuth クライアント ID |
| `oidc_client_secret <secret>` | location | — | OAuth クライアントシークレット |
| `oidc_redirect_uri <path>` | location | — | コールバック URI のパス |
| `oidc_scope <scope>` | location | `"openid"` | スコープ（スペース区切り） |
| `oidc_use_userinfo on\|off` | location | off | UserInfo エンドポイントからクレームを取得 |
| `oidc_cookie_secret <secret>` | http | — | HMAC 署名用シークレット（マルチワーカー必須） |

### 内部ロケーション

本モジュールは非同期サブリクエストで IdP と通信するため、以下の内部ロケーションを `nginx.conf` に定義する必要があります。

| ロケーション | 用途 | 注意事項 |
|------------|------|---------|
| `/_oidc_discovery` | Discovery メタデータ取得 | `proxy_pass $oidc_discovery_url;` を使用（SSRF 対策） |
| `/_oidc_token` | トークンエンドポイント | `proxy_set_body $args;` でクエリ文字列を POST ボディに変換 |
| `/_oidc_jwks` | JWKS 取得 | `proxy_pass $oidc_jwks_url;` を使用（SSRF 対策） |
| `/_oidc_userinfo` | UserInfo 取得 | `oidc_use_userinfo on;` 時のみ必要。`proxy_pass $oidc_userinfo_url;` を使用 |

### NGINX 変数

| 変数名 | 内容 |
|--------|------|
| `$oidc_claim_sub` | JWT の `sub` クレーム（ユーザーID） |
| `$oidc_claim_email` | JWT の `email` クレーム |
| `$oidc_claim_name` | JWT の `name` クレーム |
| `$oidc_claim_<name>` | JWT / UserInfo の任意クレーム（例: `$oidc_claim_groups`, `$oidc_claim_tenant_id`） |
| `$oidc_access_token` | アクセストークン（Bearer ヘッダ転送用） |
| `$oidc_discovery_url` | SSRF 対策用 Discovery URL（`/_oidc_discovery` の `proxy_pass` で使用） |
| `$oidc_jwks_url` | SSRF 対策用 JWKS URL（`/_oidc_jwks` の `proxy_pass` で使用） |
| `$oidc_userinfo_url` | SSRF 対策用 UserInfo URL（`/_oidc_userinfo` の `proxy_pass` で使用） |

継続アクセス（セッション Cookie 再利用）でも、`$oidc_claim_*` 変数はすべて Cookie から復元されます（Cookie サイズ上限: 3500 バイト）。

## 認証フロー

```
ブラウザ                   NGINX（本モジュール）                IdP
   |                             |                               |
   |─── GET /protected ─────────>|                               |
   |                        [Discoveryサブリクエスト]            |
   |                             |──── GET /_oidc_discovery ────>|
   |                             |<──── 200 JSON ────────────────|
   |                        state/nonce/code_verifier を生成     |
   |<── 302 Location: /authorize ─|                              |
   |                                                             |
   |─── GET /authorize ──────────────────────────────────────────>|
   |                         （ユーザーがログイン）              |
   |<── 302 /callback?code=...&state=... ────────────────────────|
   |                                                             |
   |─── GET /callback?code=... ─>|                               |
   |                        state / PKCE 検証                    |
   |                             |──── POST /_oidc_token ───────>|
   |                             |<──── {id_token, ...} ─────────|
   |                             |──── GET /_oidc_jwks ─────────>|
   |                             |<──── JWKS JSON ───────────────|
   |                        JWT署名検証・nonce確認               |
   |                        （oidc_use_userinfo on の場合）      |
   |                             |──── GET /_oidc_userinfo ─────>|
   |                             |<──── {claims...} ─────────────|
   |                        HMAC Cookie 発行                     |
   |<── 302 Location: /protected ─|                              |
   |                                                             |
   |─── GET /protected ──────────>|                               |
   |                        Cookie 検証 → クレーム復元           |
   |<── 200 OK ──────────────────|                               |
```

## セキュリティ

- **PKCE (S256)**: `code_verifier` を `oidc_pkce_verifier` Cookie に保存し、認証後に削除
- **state / nonce**: `RAND_bytes()` で生成した 64 文字 HEX。CSRF・リプレイ攻撃を防止
- **Cookie 属性**: すべての Cookie に `HttpOnly; Secure; SameSite=Lax; Path=/` を付与
- **タイミング攻撃対策**: Cookie の HMAC 検証に `CRYPTO_memcmp()` を使用
- **SSRF 対策**: `proxy_pass` に `$oidc_discovery_url` / `$oidc_jwks_url` 変数を使用し、URL の出所を設定値に限定
- **`oidc_cookie_secret` 未設定時**: 起動ごとにランダムシークレットを生成し `WARN` ログを出力。マルチワーカー環境では Cookie の互換性が失われるため必ず設定すること

## テスト

`test/` ディレクトリに Playwright を使った E2E テストスイートがあります。

```
test/
├── nginx.conf      # テスト用 NGINX 設定（Mock IdP を使用）
└── e2e.spec.js     # Playwright E2E テスト
```

テストは以下のシナリオを検証します:
1. 未認証アクセス → IdP へのリダイレクト
2. ログインフォーム送信 → コールバック処理 → 元 URL への復帰
3. JWT クレーム（`sub`, `email`, `name`, `groups`, `tenant_id`）のバックエンドへの引き渡し
4. セッション Cookie による継続アクセスと任意クレームの復元

## 実装状況

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | 完了 |
| Phase 2 | OIDC Discovery（非同期サブリクエスト） | 完了 |
| Phase 3 | 認証フロー・トークン交換・PKCE・state 検証 | 完了 |
| Phase 4 | JWT 署名検証・nonce 検証・セッション Cookie 発行 | 完了 |
| Phase 5 | UserInfo 対応・任意クレーム永続化・SSRF 対策 | 完了 |

### 未実装の機能

| 機能 | 説明 |
|------|------|
| RP-Initiated Logout | IdP の `/logout` エンドポイントへのリダイレクト |
| リフレッシュトークン | アクセストークンの自動更新 |
| Token Introspection | IdP への失効確認 |
| 複数プロバイダ対応 | ロケーションごとに異なる IdP を設定 |
| `oidc_ssl_trusted_certificate` | 内部 CA / 自己署名証明書の信頼設定 |
