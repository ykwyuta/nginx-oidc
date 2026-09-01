# nginx-oidc

NGINX Open Source 向けの OpenID Connect (OIDC) 認証ダイナミックモジュールです。NGINX Plus 限定だった OIDC 連携を OSS 版でも実現します。OAuth 2.0 Authorization Code Flow（PKCE 対応）を実装し、NGINX を Relying Party (RP) として動作させ、外部の Identity Provider (IdP) と連携したシングルサインオン (SSO) を提供します。

## 機能

- **Authorization Code Flow + PKCE (S256)**: 認可コード横取り攻撃を防止
- **OIDC Discovery**: `/.well-known/openid-configuration` からエンドポイントを自動取得（TTL 3600 秒、ロケーション単位でキャッシュ）
- **ID トークンの署名検証**: JWKS の公開鍵（RSA / EC）で署名を検証。`alg` は非対称署名のみ許可し、`none` と HS\* は拒否
- **ID トークンのクレーム検証**: `iss` / `aud` / `azp` / `exp` / `iat` / `nonce` を OIDC Core 3.1.3.7 に従って検証（±60 秒のクロックスキューを許容）
- **セッション管理**: HMAC-SHA256 署名付き Cookie によるステートレスセッション。`oidc_session_timeout` で有効期限を強制
- **クレーム変数**: `$oidc_claim_sub` / `$oidc_claim_email` / `$oidc_claim_name` および `$oidc_claim_<任意名>`
- **配列クレーム対応**: `groups` などが JSON 配列で返る IdP でもカンマ区切り文字列として利用可能
- **UserInfo エンドポイント**: `oidc_use_userinfo on` で追加クレームを取得（`sub` の一致を検証）
- **client_secret_basic**: クライアント認証は Authorization ヘッダで送るため、`client_secret` や認可コードがリクエストラインやログに残らない
- **SSRF 対策**: IdP の URL はすべてモジュールが提供する変数経由で `proxy_pass` に渡す
- **マルチワーカー対応**: `oidc_cookie_secret` で全ワーカー間の HMAC シークレットを統一
- **タイミング攻撃対策**: Cookie・state・nonce の比較に `CRYPTO_memcmp()` を使用
- **サーバーサイドセッション**: `oidc_session_store` で共有メモリにセッションを保持（Cookie はセッション ID のみ）
- **RP-Initiated Logout**: `oidc_logout_uri` で IdP の `end_session_endpoint` へ `id_token_hint` 付きでリダイレクト
- **リフレッシュトークン**: アクセストークンの失効時に自動更新（`oidc_refresh_token on`）
- **Token Introspection**: RFC 7662 でアクセストークンの失効を検知（`oidc_introspection on`）
- **クライアント認証**: `client_secret_basic`（既定）と `client_secret_post` を選択可能

## 依存ライブラリ

| ライブラリ | バージョン | 用途 |
|------------|-----------|------|
| OpenSSL (libssl / libcrypto) | 1.1.1 以降 | PKCE / HMAC-SHA256 / 乱数生成 / 定時間比較 |
| Jansson | 任意 | Discovery・トークン・JWKS・クレームの JSON パース |
| libjwt | 1.12 以降 | ID トークンのデコードと署名検証 |

> libjwt 1.x に JWKS を直接扱う API はありません。本モジュールは JWKS の JWK から
> SubjectPublicKeyInfo (PEM) を組み立て、その公開鍵を `jwt_decode()` に渡して署名を検証します。

## ビルド

```bash
# NGINX ソースディレクトリで
./configure --with-compat --add-dynamic-module=/path/to/nginx-oidc
make modules

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
    # マルチワーカー構成では必須。openssl rand -hex 32 で生成した値を設定する。
    oidc_cookie_secret "your-random-secret-here";

    # 必須: $oidc_*_url を proxy_pass に使うため、IdP のホスト名は実行時に解決される。
    # resolver が無いと "no resolver defined to resolve <host>" で失敗する。
    resolver 127.0.0.53 ipv6=off valid=300s;

    # セッションを共有メモリに保持する（推奨）。
    # ログアウトの id_token_hint・リフレッシュトークン・イントロスペクションは
    # トークンを保持する必要があるため、この設定が前提となる。
    oidc_session_store 10m;

    server {
        listen 443 ssl;

        # ---- IdP と通信する内部ロケーション ----

        location = /_oidc_discovery {
            internal;
            proxy_pass $oidc_discovery_url;

            # HTTPS の IdP では upstream の証明書検証を必ず有効にすること
            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_verify_depth        2;
            proxy_ssl_server_name         on;
        }

        location = /_oidc_token {
            internal;
            proxy_pass       $oidc_token_url;
            proxy_method     POST;
            proxy_set_header Content-Type  "application/x-www-form-urlencoded";
            proxy_set_header Authorization $oidc_token_basic;
            proxy_set_body   $oidc_token_body;

            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_server_name         on;
        }

        location = /_oidc_jwks {
            internal;
            proxy_pass $oidc_jwks_url;

            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_server_name         on;
        }

        # oidc_use_userinfo on; のときのみ必要
        location = /_oidc_userinfo {
            internal;
            proxy_pass       $oidc_userinfo_url;
            proxy_set_header Authorization $oidc_userinfo_bearer;

            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_server_name         on;
        }

        # oidc_introspection on; のときのみ必要
        location = /_oidc_introspect {
            internal;
            proxy_pass       $oidc_introspect_url;
            proxy_method     POST;
            proxy_set_header Content-Type  "application/x-www-form-urlencoded";
            proxy_set_header Authorization $oidc_token_basic;
            proxy_set_body   $oidc_introspect_body;

            proxy_ssl_verify              on;
            proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
            proxy_ssl_server_name         on;
        }

        # ---- 保護するロケーション ----

        location / {
            auth_oidc          on;
            oidc_provider      "https://idp.example.com/realms/myrealm";
            oidc_client_id     "my-client";
            oidc_client_secret "secret";
            oidc_redirect_uri  "https://app.example.com/callback";
            oidc_scope         "openid profile email";
            # oidc_use_userinfo on;      # UserInfo から追加クレームを取得する場合
            # oidc_session_timeout 1h;   # 既定値
            # oidc_claims groups roles;  # セッションに載せるクレームを限定する場合

            # ログアウト（このロケーション配下のパスを指定する）
            oidc_logout_uri               "https://app.example.com/logout";
            oidc_post_logout_redirect_uri "https://app.example.com/";

            # 任意: アクセストークンの自動更新と失効確認（oidc_session_store が必要）
            # oidc_refresh_token          on;
            # oidc_introspection          on;
            # oidc_introspection_interval 60s;

            # 任意: クライアント認証方式（既定は basic）
            # oidc_client_auth post;

            # 任意: 認可リクエストへの追加パラメータ
            # oidc_auth_request_args "prompt=select_account";

            proxy_pass http://backend;
            proxy_set_header X-Remote-User   $oidc_claim_sub;
            proxy_set_header X-Remote-Email  $oidc_claim_email;
            proxy_set_header X-Remote-Name   $oidc_claim_name;
            proxy_set_header X-Remote-Groups $oidc_claim_groups;
            # アクセストークンをバックエンドに渡す場合（初回認証リクエストのみ）:
            # proxy_set_header Authorization "Bearer $oidc_access_token";
        }
    }
}
```

`oidc_redirect_uri` には IdP に登録した**絶対 URI** を指定してください。パスだけを書くこともできますが、その場合は IdP へ送る `redirect_uri` もパスのみになるため、多くの IdP に拒否されます。コールバックの判定にはこの URI のパス部分が完全一致で使われます。

**コールバックとログアウトのパスは、保護対象と同じ location にマッチさせてください。** トークン交換はコールバックのリクエストで行われるため、`oidc_client_id` などの設定はコールバック URI がマッチする location のものが使われます。上の例のように `location /` で受ける場合は問題ありませんが、`location /app/` だけを保護する場合は `oidc_redirect_uri "https://app.example.com/app/callback"` のように配下に置きます。

### ディレクティブ一覧

| ディレクティブ | コンテキスト | デフォルト | 説明 |
|--------------|------------|-----------|------|
| `auth_oidc on\|off` | http, server, location | off | OIDC 認証の有効/無効 |
| `oidc_provider <url>` | http, server, location | — | IdP の issuer URL（Discovery に使用） |
| `oidc_client_id <id>` | http, server, location | — | OAuth クライアント ID |
| `oidc_client_secret <secret>` | http, server, location | — | OAuth クライアントシークレット |
| `oidc_redirect_uri <uri>` | http, server, location | — | コールバック URI（IdP 登録済みの絶対 URI 推奨） |
| `oidc_scope <scope>` | http, server, location | `"openid"` | スコープ（スペース区切り） |
| `oidc_use_userinfo on\|off` | http, server, location | off | UserInfo エンドポイントからクレームを取得 |
| `oidc_session_timeout <time>` | http, server, location | `1h` | セッション Cookie の有効期間。`0` で無効（非推奨） |
| `oidc_claims <name>...` | http, server, location | — | `$oidc_claim_*` として公開しセッションに保存するクレームを限定 |
| `oidc_logout_uri <uri>` | http, server, location | — | このパスへのリクエストでログアウトする（RP-Initiated Logout） |
| `oidc_post_logout_redirect_uri <uri>` | http, server, location | — | ログアウト後の戻り先。IdP に登録が必要 |
| `oidc_client_auth basic\|post` | http, server, location | basic | トークン／イントロスペクションのクライアント認証方式 |
| `oidc_refresh_token on\|off` | http, server, location | off | アクセストークン失効時にリフレッシュトークンで更新（`oidc_session_store` が必要） |
| `oidc_introspection on\|off` | http, server, location | off | アクセストークンの失効確認（RFC 7662、`oidc_session_store` が必要） |
| `oidc_introspection_interval <time>` | http, server, location | `60s` | 同一セッションに対する失効確認の間隔 |
| `oidc_auth_request_args <value>` | http, server, location | — | 認可リクエストに付ける追加パラメータ（変数使用可） |
| `oidc_session_store <size>` | http | — | セッションを共有メモリに保持する（例 `10m`）。最小 8 ページ |
| `oidc_cookie_secret <secret>` | http | — | セッション Cookie の HMAC シークレット（Cookie モードで必須） |

`oidc_claims` を指定しない場合、プロトコルクレーム（`iss` `aud` `exp` `iat` `nbf` `jti` `nonce` `azp` `at_hash` `c_hash` `s_hash` `auth_time` `sid` `typ` `session_state`）を除くすべてのクレームが取り込まれます。

### セッションの保存方式

| | Cookie モード（既定） | ストアモード（`oidc_session_store`） |
|---|---|---|
| Cookie の内容 | HMAC 署名 + クレーム | 256 bit のセッション ID のみ |
| クレームの上限 | 3500 バイト | 事実上なし |
| ID トークン / アクセストークン / リフレッシュトークン | 初回認証リクエストのみ保持 | セッションが生きている間ずっと保持 |
| `$oidc_id_token` / `$oidc_access_token` | 初回認証リクエストのみ | 常に利用可能 |
| ログアウト時の `id_token_hint` | 付かない | 付く |
| `oidc_refresh_token` / `oidc_introspection` | 利用不可 | 利用可能 |
| 追加のメモリ | なし | `oidc_session_store` のサイズ |
| NGINX 再起動 | セッション維持 | セッション消失（再認証になる） |

ストアが満杯になると古いセッションから順に追い出されます。1 セッションあたりおよそ「クレーム + 各トークンの長さ + 150 バイト」を消費します。

### 内部ロケーション

本モジュールは非同期サブリクエストで IdP と通信するため、以下の内部ロケーションを定義する必要があります。`proxy_pass` には必ず下表の変数を使ってください（URL の出所を Discovery の結果に限定するための SSRF 対策です）。

| ロケーション | 必須の設定 |
|------------|-----------|
| `/_oidc_discovery` | `proxy_pass $oidc_discovery_url;` |
| `/_oidc_token` | `proxy_pass $oidc_token_url;` + `proxy_method POST;` + `proxy_set_body $oidc_token_body;` + `Authorization: $oidc_token_basic` |
| `/_oidc_jwks` | `proxy_pass $oidc_jwks_url;` |
| `/_oidc_userinfo` | `proxy_pass $oidc_userinfo_url;` + `Authorization: $oidc_userinfo_bearer`（`oidc_use_userinfo on` 時のみ） |
| `/_oidc_introspect` | `proxy_pass $oidc_introspect_url;` + `proxy_method POST;` + `proxy_set_body $oidc_introspect_body;` + `Authorization: $oidc_token_basic`（`oidc_introspection on` 時のみ） |

`/_oidc_token` で `proxy_set_header Content-Length "";` を指定してはいけません。`proxy_set_body` が設定する Content-Length が消え、リクエストボディが IdP に届かなくなります。

### NGINX 変数

| 変数名 | 内容 |
|--------|------|
| `$oidc_claim_sub` | ID トークンの `sub`（ユーザー ID） |
| `$oidc_claim_email` | ID トークン / UserInfo の `email` |
| `$oidc_claim_name` | ID トークン / UserInfo の `name` |
| `$oidc_claim_<name>` | 任意クレーム（例 `$oidc_claim_groups`, `$oidc_claim_tenant_id`）。配列はカンマ区切りに展開 |
| `$oidc_access_token` | アクセストークン（Cookie モードでは初回認証リクエストのみ） |
| `$oidc_id_token` | ID トークン（Cookie モードでは初回認証リクエストのみ） |
| `$oidc_discovery_url` | Discovery URL（`/_oidc_discovery` 用） |
| `$oidc_token_url` | トークンエンドポイント URL（`/_oidc_token` 用） |
| `$oidc_jwks_url` | JWKS URL（`/_oidc_jwks` 用） |
| `$oidc_userinfo_url` | UserInfo URL（`/_oidc_userinfo` 用） |
| `$oidc_token_body` | トークンリクエストのボディ（`proxy_set_body` 用） |
| `$oidc_token_basic` | `Basic base64(client_id:client_secret)`（`Authorization` ヘッダ用） |
| `$oidc_userinfo_bearer` | `Bearer <access_token>`（`Authorization` ヘッダ用） |
| `$oidc_introspect_url` | イントロスペクションエンドポイント URL（`/_oidc_introspect` 用） |
| `$oidc_introspect_body` | イントロスペクションリクエストのボディ（`proxy_set_body` 用） |

継続アクセス（セッション Cookie 再利用）でも `$oidc_claim_*` はすべて Cookie から復元されます（Cookie ペイロード上限 3500 バイト）。

## 認証フロー

```
ブラウザ                   NGINX（本モジュール）                IdP
   |                             |                               |
   |─── GET /protected ─────────>|                               |
   |                        [Discovery サブリクエスト]           |
   |                             |──── GET /_oidc_discovery ────>|
   |                             |<──── 200 JSON ────────────────|
   |                        issuer が oidc_provider と一致するか検証
   |                        state / nonce / code_verifier を生成 |
   |<── 302 Location: /authorize ─|                              |
   |                                                             |
   |─── GET /authorize ──────────────────────────────────────────>|
   |                         （ユーザーがログイン）              |
   |<── 302 /callback?code=...&state=... ────────────────────────|
   |                                                             |
   |─── GET /callback?code=... ─>|                               |
   |                        state を定時間比較で検証             |
   |                             |──── POST /_oidc_token ───────>|
   |                             |     Authorization: Basic ...  |
   |                             |     body: code/verifier/...   |
   |                             |<──── {id_token, ...} ─────────|
   |                             |──── GET /_oidc_jwks ─────────>|
   |                             |<──── JWKS JSON ───────────────|
   |                        JWKS の公開鍵で署名検証              |
   |                        iss / aud / exp / iat / nonce を検証 |
   |                        （oidc_use_userinfo on の場合）      |
   |                             |──── GET /_oidc_userinfo ─────>|
   |                             |<──── {claims...} ─────────────|
   |                        sub の一致を確認しクレームをマージ   |
   |                        HMAC 署名付きセッション Cookie を発行|
   |<── 302 Location: /protected ─|                              |
   |                                                             |
   |─── GET /protected ──────────>|                               |
   |                        Cookie 署名と有効期限を検証          |
   |<── 200 OK ──────────────────|                               |
```

## ログアウト

`oidc_logout_uri` に設定したパスへのリクエストで以下を行います。

1. サーバーサイドセッション（ストアモード時）を破棄する
2. `oidc_auth` とログイン処理用の Cookie を削除する
3. IdP が `end_session_endpoint` を公開していれば、`client_id` と（ストアモード時は）`id_token_hint`、`oidc_post_logout_redirect_uri` を付けてそこへ 302
4. 公開していなければ `oidc_post_logout_redirect_uri`（未設定なら `/`）へ 302

`oidc_post_logout_redirect_uri` は IdP 側にも登録が必要です。ログアウト後の戻り先は認証不要にしておいてください（`auth_oidc off;`）。

## トークンの更新と失効確認

`oidc_session_store` が有効なとき、保護対象へのリクエストごとに次を行います。

- `oidc_refresh_token on`: アクセストークンの有効期限が切れていれば、リフレッシュトークンで再取得する。新しい ID トークンが返った場合は署名と `iss` / `aud` / `sub` を検証してからセッションを更新し、`oidc_auth` Cookie の Max-Age も更新する。更新に失敗した場合はセッションを破棄して再認証にフォールバックする
- `oidc_introspection on`: 前回の確認から `oidc_introspection_interval` 以上経過していれば、イントロスペクションエンドポイントに問い合わせる。`active: false` ならセッションを破棄して再認証にする

いずれも非同期サブリクエストで行うため、イベントループはブロックしません。

## セキュリティ

- **ID トークンの署名検証**: JWKS の `kid` に一致する鍵で検証。`kty` と `alg` の整合性を確認し、`alg` は RS256/384/512・PS256/384/512・ES256/384/512 のみ許可（`none` と HS\* は拒否）
- **クレーム検証**: `iss` は Discovery の `issuer` と一致すること、`aud` は `oidc_client_id` を含むこと、`aud` が複数なら `azp` が一致すること、`exp` が未来であること、`iat` が未来でないこと、`nonce` が Cookie と一致すること
- **Discovery の検証**: 取得した文書の `issuer` が `oidc_provider` と一致しない場合は拒否（OIDC Discovery 4.3）
- **PKCE (S256)**: `code_verifier` を `oidc_pkce_verifier` Cookie に保存し、認証完了後に削除
- **state / nonce**: `RAND_bytes()` による 64 文字 HEX。比較は `CRYPTO_memcmp()`
- **Cookie 属性**: すべての Cookie に `HttpOnly; Secure; SameSite=Lax; Path=/`。ログイン処理用 Cookie は Max-Age 600 秒、セッション Cookie は `oidc_session_timeout`
- **セッション有効期限**: Cookie に記録した発行時刻を毎リクエスト検証し、`oidc_session_timeout` を超えたら再認証
- **オープンリダイレクト対策**: 認証後の戻り先はローカルパスのみ許可（`//host` や `/\host` は拒否、制御文字も拒否）
- **秘密情報をログに残さない**: `client_secret` は Authorization ヘッダ、認可コードと `code_verifier` はリクエストボディ、アクセストークンは Authorization ヘッダで送るため、リクエストラインやアクセスログに載らない
- **SSRF 対策**: `proxy_pass` に渡す URL はモジュールが Discovery 結果から組み立てた変数のみ
- **upstream の TLS 検証**: NGINX の既定では `proxy_ssl_verify` は off。HTTPS の IdP を使う場合は上記の設定例のとおり必ず有効にすること
- **`oidc_cookie_secret` 未設定時**: 起動ごとにワーカーがランダムシークレットを生成し `WARN` を出力。Cookie モードのマルチワーカー環境では必ず設定すること（ストアモードでは Cookie に署名しないため不要）
- **リフレッシュトークンの保管**: リフレッシュトークンは共有メモリのセッションにのみ保持し、Cookie には出さない
- **失効の検知**: `oidc_introspection on` でアクセストークンの失効を検知しセッションを破棄する。イントロスペクションエンドポイントに到達できない場合はセッションを維持し（フェイルオープン）警告ログを出す。タイムスタンプを更新しないため次のリクエストで再試行する

## テスト

`test/` に実モジュールを対象とした Playwright E2E テストがあります。

```bash
cd test && npm install && npx playwright install chromium
NGINX_SRC=/path/to/nginx-1.26.2 ./test/run-e2e.sh
```

`run-e2e.sh` はモジュールのビルド、モック IdP 2 台（RS256 / ES256）の起動、NGINX の起動、Playwright の実行、後片付けまでを行い、**セッションストアあり・なしの両方**でテストします。詳細は [TEST_PLAYWRIGHT.md](TEST_PLAYWRIGHT.md) を参照してください。

検証シナリオ:

1. 未認証アクセス → IdP へのリダイレクト（PKCE パラメータを含む）
2. ログイン → コールバック → 元 URL への復帰とクレームのバックエンドへの引き渡し
3. UserInfo が配列で返す `groups` のカンマ区切り展開
4. セッションによる継続アクセス
5. セッションにプロトコルクレームが載らないこと
6. セッション Cookie 改竄時の再認証
7. state 不一致時の 403
8. JWKS にない鍵で署名した ID トークンの拒否（401）
9. `aud` が別クライアントの ID トークンの拒否（401）
10. `oidc_session_timeout` 経過後の再認証
11. ロケーションごとに別プロバイダ（別ポート・ES256）を使えること
12. コールバックパスの完全一致判定
13. `oidc_auth_request_args` が認可リクエストに付くこと
14. `client_secret_post` でのクライアント認証
15. 継続リクエストでの `$oidc_id_token`（ストアモード）
16. アクセストークン失効時のリフレッシュトークンによる自動更新（ストアモード）
17. イントロスペクションが `active: false` を返したときのセッション破棄（ストアモード）
18. RP-Initiated Logout（`id_token_hint` と `post_logout_redirect_uri` を含む）

## 実装状況

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | 完了 |
| Phase 2 | OIDC Discovery（非同期サブリクエスト・issuer 検証） | 完了 |
| Phase 3 | 認証フロー・トークン交換・PKCE・state 検証 | 完了 |
| Phase 4 | ID トークンの署名検証・クレーム検証・セッション Cookie | 完了 |
| Phase 5 | UserInfo・任意クレーム永続化・SSRF 対策・実モジュール E2E | 完了 |
| Phase 6 | サーバーサイドセッション・ログアウト・リフレッシュ・イントロスペクション | 完了 |

### 未実装の機能

| 機能 | 説明 |
|------|------|
| Back-Channel / Front-Channel Logout | IdP からの通知でセッションを破棄する方式。現状は RP-Initiated Logout のみ |
| 外部セッションストア（Redis 等） | 共有メモリはホスト内で共有される。複数ホスト間で共有するには外部ストアが必要 |
| `private_key_jwt` / `client_secret_jwt` | クライアント認証は `client_secret_basic` と `client_secret_post` のみ |
| `oidc_provider` ブロック構文 | NGINX Plus モジュールとの設定互換 |
