# nginx-oidc

NGINX Plus の OIDC 認証機能と互換性のある NGINX 拡張モジュールです。
商用の NGINX Plus を使わずに、オープンソース NGINX 上で OpenID Connect (OIDC) による SSO 認証を実現します。

## 背景・目的

NGINX Plus は Release 34 以降でネイティブの OIDC 認証機能を提供していますが、これは商用ライセンスが必要です。
本プロジェクトは NGINX JavaScript (njs) モジュールを用いて、以下を目的とします。

- NGINX Plus の OIDC 機能と同等の設定インターフェースを OSS NGINX 上で実現する
- `oidc_provider {}` や `auth_oidc` といった疑似ディレクティブを njs + include 構成で模倣し、移行コストを最小化する
- Auth0 / Okta / Keycloak / Microsoft Entra ID / AWS Cognito などの主要 IdP に対応する

## アーキテクチャ概要

```
クライアント
    │
    ▼
┌─────────────────────────────────────────┐
│  NGINX (OSS + njs module)               │
│                                         │
│  ┌─────────────────────────────────┐    │
│  │  oidc.js  (njs スクリプト)      │    │
│  │  - 認可コードフロー制御          │    │
│  │  - トークン取得・検証            │    │
│  │  - セッション管理                │    │
│  │  - ログアウト処理               │    │
│  └─────────────────────────────────┘    │
│                                         │
│  共有メモリゾーン (njs 共有辞書)         │
│  - セッション → トークンのマッピング     │
└─────────────────────────────────────────┘
    │                          │
    ▼                          ▼
バックエンドアプリ          IdP (Identity Provider)
(X-OIDC-* ヘッダーで        (Keycloak, Auth0, Okta, etc.)
 クレームを受け取る)
```

### 認証フロー (Authorization Code Flow)

```
1. クライアント → NGINX: 保護リソースへのリクエスト
2. NGINX: セッション Cookie 確認 → 未認証なら IdP へリダイレクト
3. IdP: ユーザー認証 → 認可コード付きで NGINX のコールバック URI へリダイレクト
4. NGINX (njs): 認可コードをトークンエンドポイントに送信
5. IdP → NGINX: ID トークン / アクセストークン / リフレッシュトークンを返す
6. NGINX (njs): ID トークン (JWT) を検証 (署名・有効期限・nonce・issuer・audience)
7. NGINX: セッション ID を生成し共有メモリに保存、Set-Cookie で返す
8. NGINX: クレームをリクエストヘッダーに設定し、バックエンドへプロキシ
```

## 機能要件

### コア機能

| 機能 | 説明 | NGINX Plus 対応ディレクティブ |
|------|------|-------------------------------|
| IdP メタデータ自動取得 | `.well-known/openid-configuration` からエンドポイントを自動検出 | `config_url` / `issuer` |
| 認可コードフロー | PKCE 対応の Authorization Code Flow を実装 | `auth_oidc` |
| JWT 検証 | 署名 (RS256/ES256)・有効期限・issuer・audience・nonce を検証 | 自動 |
| セッション管理 | 暗号化 Cookie + NGINX 共有メモリによるサーバーサイドセッション | 自動 |
| クレーム転送 | ID トークンのクレームをバックエンドへのリクエストヘッダーとして転送 | `$oidc_claim_*` 変数 |
| トークンリフレッシュ | アクセストークン期限切れ時にリフレッシュトークンで自動更新 | 自動 |
| RP-initiated ログアウト | IdP 側のセッションも含めたログアウト | `logout_uri` / `post_logout_uri` |
| UserInfo エンドポイント | 追加のユーザープロファイル情報の取得 | `userinfo` |

### 対応 IdP

- Keycloak
- Auth0
- Okta
- Microsoft Entra ID (Azure AD)
- AWS Cognito
- Google Identity Platform
- OIDC 準拠のすべての IdP (汎用対応)

### セキュリティ要件

- state パラメータによる CSRF 防止
- PKCE (Proof Key for Code Exchange) の実装
- nonce によるリプレイアタック防止
- セッション Cookie の `HttpOnly` / `Secure` / `SameSite=Lax` 属性
- セッション固定攻撃対策 (認証後のセッション ID 再生成)
- IdP 証明書の TLS 検証

## 実装方針

### 技術スタック

| コンポーネント | 採用技術 | 採用理由 |
|---------------|----------|----------|
| NGINX モジュール | **njs (NGINX JavaScript)** | OSS NGINX に同梱可能・サブリクエスト API あり・追加インストールが容易 |
| セッションストア | njs `js_shared_dict_zone` (共有メモリ) | 追加 DB 不要・ワーカープロセス間で共有可能 |
| JWT 検証 | njs 組み込み Crypto API | 外部依存なし |
| JWK 取得 | njs `ngx.fetch` | 非同期 HTTP リクエスト対応 |

### ファイル構成 (予定)

```
nginx-oidc/
├── README.md
├── njs/
│   ├── oidc.js          # メインの OIDC フロー処理
│   ├── jwt.js           # JWT パース・検証ユーティリティ
│   ├── jwks.js          # JWK Set の取得・キャッシュ
│   └── session.js       # セッション管理
├── nginx/
│   ├── oidc_provider.conf.template   # IdP 設定テンプレート
│   ├── oidc_location.conf            # OIDC 処理用 location ブロック
│   └── example/
│       ├── nginx.conf               # サンプル設定 (Keycloak)
│       └── nginx-auth0.conf         # サンプル設定 (Auth0)
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml           # NGINX + Keycloak の開発環境
└── tests/
    ├── unit/
    └── integration/
```

### NGINX Plus 互換の設定インターフェース

NGINX Plus の設定構文をできる限り模倣し、移行を容易にします。

**NGINX Plus (参考):**
```nginx
oidc_provider my_idp {
    issuer        https://idp.example.com/realms/myrealm;
    client_id     my-app;
    client_secret $secret;
}

server {
    location /app {
        auth_oidc my_idp;
        proxy_set_header X-User-Sub $oidc_claim_sub;
        proxy_pass http://backend;
    }
}
```

**本拡張 (実装予定):**
```nginx
# njs モジュールの読み込み
load_module modules/ngx_http_js_module.so;

js_import njs/oidc.js;
js_shared_dict_zone zone=oidc_sessions:1m timeout=8h;

# IdP 設定 (map ブロックで模倣)
include nginx/oidc_provider.conf;  # issuer, client_id 等を定義

server {
    # OIDC コールバック・ログアウト処理用 location
    include nginx/oidc_location.conf;

    location /app {
        # 認証チェック (auth_oidc に相当)
        auth_request /_oidc_auth;

        proxy_set_header X-User-Sub   $oidc_claim_sub;
        proxy_set_header X-User-Email $oidc_claim_email;
        proxy_pass http://backend;
    }
}
```

### セッション管理の設計

```
Cookie: oidc_session=<session_id (256-bit random, base64url)>

共有メモリ (njs 共有辞書):
  Key: <session_id>
  Value: JSON {
    "sub":           "user123",
    "access_token":  "...",
    "refresh_token": "...",
    "id_token":      "...",
    "expires_at":    1234567890,
    "claims": { "email": "...", "name": "..." }
  }
```

### エラーハンドリング方針

- IdP への接続失敗: 503 を返し、エラーページを表示
- JWT 検証失敗: セッションを削除し、再認証フローへ
- リフレッシュトークン期限切れ: 再認証フローへ
- 設定ミス: NGINX 起動時に早期エラーで検出

## 非機能要件

| 項目 | 目標値 |
|------|--------|
| 認証済みリクエストのレイテンシオーバーヘッド | < 1ms (セッションヒット時) |
| JWK キャッシュ TTL | 1時間 (IdP のローテーションに追従) |
| セッション有効期限 | デフォルト 8 時間 (設定可能) |
| 同時セッション数 | 共有メモリサイズに依存 (デフォルト 1MB ≒ 4,000 セッション) |
| 対応 NGINX バージョン | 1.21.0 以上 (njs 0.7.0 以上) |

## 開発ロードマップ

### Phase 1: コア OIDC フロー
- [ ] njs による認可コードフロー実装
- [ ] JWT 署名検証 (RS256 / ES256)
- [ ] JWK Set の取得とキャッシュ
- [ ] セッション管理 (njs 共有辞書)
- [ ] Keycloak での動作確認

### Phase 2: 互換性強化
- [ ] PKCE サポート
- [ ] UserInfo エンドポイント対応
- [ ] トークン自動リフレッシュ
- [ ] RP-initiated ログアウト
- [ ] `$oidc_claim_*` 変数の実装

### Phase 3: IdP 対応拡充・運用機能
- [ ] Auth0 / Okta / Microsoft Entra ID 動作確認
- [ ] Redis バックエンドによる分散セッション対応
- [ ] メトリクス公開 (`/oidc_status` エンドポイント)
- [ ] Docker Compose による開発環境整備
- [ ] 統合テストスイート

## 前提条件

- NGINX 1.21.0 以上
- `ngx_http_js_module` (njs モジュール)
- `ngx_http_auth_request_module`
- OpenID Connect 準拠の IdP

### njs モジュールのインストール

```bash
# Debian/Ubuntu
apt-get install nginx-module-njs

# RHEL/CentOS
yum install nginx-module-njs

# nginx.conf に追加
load_module modules/ngx_http_js_module.so;
```

## ライセンス

MIT License

## 参考資料

- [NGINX Plus OIDC 設定ガイド](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-oidc/)
- [NGINX JavaScript (njs) ドキュメント](https://nginx.org/en/docs/njs/)
- [OpenID Connect Core 1.0 仕様](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636 - PKCE](https://tools.ietf.org/html/rfc7636)
- [NGINX 公式 OpenID Connect リファレンス実装](https://github.com/nginxinc/nginx-openid-connect)
