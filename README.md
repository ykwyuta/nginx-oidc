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
- **サーバーサイドセッション**: `oidc_session_store` で共有メモリまたは **Redis** にセッションを保持（Cookie はセッション ID のみ）
- **RP-Initiated Logout**: `oidc_logout_uri` で IdP の `end_session_endpoint` へ `id_token_hint` 付きでリダイレクト
- **リフレッシュトークン**: アクセストークンの失効時に自動更新（`oidc_refresh_token on`）
- **Token Introspection**: RFC 7662 でアクセストークンの失効を検知（`oidc_introspection on`）
- **クライアント認証**: `client_secret_basic`（既定）/ `client_secret_post` / `client_secret_jwt` / `private_key_jwt`
- **Back-Channel / Front-Channel Logout**: IdP からの通知で該当セッションを破棄
- **`oidc_provider` ブロック**: NGINX Plus 互換の名前付きプロバイダ定義
- **Pushed Authorization Requests (PAR)**: RFC 9126。認可リクエストをバックチャネルで先に送り、ブラウザには `request_uri` だけを渡す
- **DPoP**: RFC 9449。EC 鍵で proof を作り、トークン / UserInfo / バックエンドへのリクエストを鍵に紐付ける
- **mTLS クライアント認証**: RFC 8705。クライアント証明書で認証し、`mtls_endpoint_aliases` のトークン / イントロスペクションエンドポイントがあればそちらを使う
- **Redis Sentinel / Cluster**: Sentinel でマスターを解決してフェイルオーバーに追従、Cluster では slot 単位のルーティングと MOVED / ASK の追従

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

    # セッションの保存先。サイズを指定すると共有メモリ、redis と書くと Redis。
    # ログアウトの id_token_hint・リフレッシュトークン・イントロスペクション・
    # Back-Channel / Front-Channel Logout はトークンやインデックスの保持が
    # 必要なため、いずれかの設定が前提となる。
    oidc_session_store 10m;
    # oidc_session_store redis;

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

        # oidc_session_store redis; のときのみ必要
        location = /_oidc_redis {
            internal;
            oidc_redis_pass 127.0.0.1:6379;
            # oidc_redis_password "...";
            # oidc_redis_database 0;
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

            # IdP からのログアウト通知を受ける（oidc_session_store が必要）
            oidc_backchannel_logout_uri   "https://app.example.com/backchannel-logout";
            oidc_frontchannel_logout_uri  "https://app.example.com/frontchannel-logout";

            # 任意: アクセストークンの自動更新と失効確認（oidc_session_store が必要）
            # oidc_refresh_token          on;
            # oidc_introspection          on;
            # oidc_introspection_interval 60s;

            # 任意: クライアント認証方式（既定は basic）
            # oidc_client_auth post;
            # oidc_client_auth private_key_jwt;
            # oidc_client_jwt_key /etc/nginx/oidc-client.key;
            # oidc_client_jwt_kid "my-key-1";

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
| `oidc_provider <url>` | server, location | — | IdP の issuer URL（Discovery に使用） |
| `oidc_provider <name> { ... }` | http | — | 名前付きプロバイダの定義（NGINX Plus 互換） |
| `oidc_client_id <id>` | http, server, location | — | OAuth クライアント ID |
| `oidc_client_secret <secret>` | http, server, location | — | OAuth クライアントシークレット |
| `oidc_redirect_uri <uri>` | http, server, location | — | コールバック URI（IdP 登録済みの絶対 URI 推奨） |
| `oidc_scope <scope>` | http, server, location | `"openid"` | スコープ（スペース区切り） |
| `oidc_use_userinfo on\|off` | http, server, location | off | UserInfo エンドポイントからクレームを取得 |
| `oidc_session_timeout <time>` | http, server, location | `1h` | セッション Cookie の有効期間。`0` で無効（非推奨） |
| `oidc_claims <name>...` | http, server, location | — | `$oidc_claim_*` として公開しセッションに保存するクレームを限定 |
| `oidc_logout_uri <uri>` | http, server, location | — | このパスへのリクエストでログアウトする（RP-Initiated Logout） |
| `oidc_post_logout_redirect_uri <uri>` | http, server, location | — | ログアウト後の戻り先。IdP に登録が必要 |
| `oidc_client_auth <method>` | http, server, location | basic | `basic` / `post` / `client_secret_jwt` / `private_key_jwt` / `mtls` |
| `oidc_refresh_token on\|off` | http, server, location | off | アクセストークン失効時にリフレッシュトークンで更新（`oidc_session_store` が必要） |
| `oidc_introspection on\|off` | http, server, location | off | アクセストークンの失効確認（RFC 7662、`oidc_session_store` が必要） |
| `oidc_introspection_interval <time>` | http, server, location | `60s` | 同一セッションに対する失効確認の間隔 |
| `oidc_auth_request_args <value>` | http, server, location | — | 認可リクエストに付ける追加パラメータ（変数使用可） |
| `oidc_backchannel_logout_uri <uri>` | http, server, location | — | IdP が logout token を POST してくるエンドポイント |
| `oidc_frontchannel_logout_uri <uri>` | http, server, location | — | IdP が iframe で読み込むログアウトエンドポイント |
| `oidc_client_jwt_key <file>` | http, server, location | — | `private_key_jwt` の署名に使う PEM 秘密鍵 |
| `oidc_client_jwt_kid <kid>` | http, server, location | — | client assertion の `kid` ヘッダ |
| `oidc_client_jwt_alg <alg>` | http, server, location | RS256 / HS256 | client assertion の署名アルゴリズム |
| `oidc_par on\|off` | http, server, location | プロバイダ設定に従う | 認可リクエストを PAR で先に送る（RFC 9126） |
| `oidc_dpop on\|off` | http, server, location | off | DPoP でトークンを鍵に紐付ける（RFC 9449、`oidc_dpop_key` が必要） |
| `oidc_dpop_key <file>` | http, server, location | — | proof の署名に使う EC 秘密鍵（P-256 / P-384 / P-521） |
| `oidc_dpop_htu <value>` | http, server, location | — | `$oidc_dpop_backend_proof` の `htu`（変数使用可） |
| `oidc_session_store <size\|redis>` | http | — | セッションの保存先。サイズなら共有メモリ（例 `10m`、最小 8 ページ）、`redis` なら Redis |
| `oidc_redis_pass <addr>` | location | — | Redis の宛先（`/_oidc_redis` ロケーションに書く） |
| `oidc_redis_sentinel <addr>...` | http | — | Sentinel の宛先。ここからマスターを解決する（`oidc_redis_master` が必要） |
| `oidc_redis_master <name>` | http | — | Sentinel に問い合わせるマスター名 |
| `oidc_redis_cluster on\|off` | http | off | Redis Cluster として扱い、slot でルーティングして MOVED / ASK を追う |
| `oidc_redis_password <pw>` | http, server, location | — | Redis の AUTH パスワード |
| `oidc_redis_database <n>` | http, server, location | 0 | Redis のデータベース番号 |
| `oidc_redis_connect_timeout <t>` | http, server, location | `5s` | Redis への接続タイムアウト |
| `oidc_redis_send_timeout <t>` | http, server, location | `5s` | Redis への送信タイムアウト |
| `oidc_redis_read_timeout <t>` | http, server, location | `5s` | Redis からの受信タイムアウト |
| `oidc_redis_buffer_size <size>` | http, server, location | `16k` | Redis 応答の読み取りバッファ。セッション 1 件分が収まる必要がある |
| `oidc_cookie_secret <secret>` | http | — | セッション Cookie の HMAC シークレット（Cookie モードで必須） |

`oidc_claims` を指定しない場合、プロトコルクレーム（`iss` `aud` `exp` `iat` `nbf` `jti` `nonce` `azp` `at_hash` `c_hash` `s_hash` `auth_time` `sid` `typ` `session_state`）を除くすべてのクレームが取り込まれます。

### セッションの保存方式

| | Cookie（既定） | 共有メモリ（`oidc_session_store <size>`） | Redis（`oidc_session_store redis`） |
|---|---|---|---|
| Cookie の内容 | HMAC 署名 + クレーム | 256 bit のセッション ID のみ | 256 bit のセッション ID のみ |
| クレームの上限 | 3500 バイト | 事実上なし | 事実上なし |
| ID / アクセス / リフレッシュトークン | 初回認証リクエストのみ保持 | セッションが生きている間ずっと保持 | 同左 |
| `$oidc_id_token` / `$oidc_access_token` | 初回認証リクエストのみ | 常に利用可能 | 常に利用可能 |
| ログアウト時の `id_token_hint` | 付かない | 付く | 付く |
| `oidc_refresh_token` / `oidc_introspection` | 利用不可 | 利用可能 | 利用可能 |
| Back-Channel / Front-Channel Logout | 利用不可 | 利用可能 | 利用可能 |
| 複数ホスト間の共有 | 不可（各ホストが自分で検証） | 不可（ホスト内のみ） | **可能** |
| NGINX 再起動 | セッション維持 | セッション消失 | セッション維持 |
| 追加の依存 | なし | 共有メモリのみ | Redis サーバー |

共有メモリのストアが満杯になると古いセッションから順に追い出されます。1 セッションあたりおよそ「クレーム + 各トークンの長さ + 150 バイト」を消費します。

Redis を使う場合の注意:

- `/_oidc_redis` ロケーションを定義し、`oidc_redis_pass` で宛先を指定します。`upstream` ブロックを宛先にすれば `keepalive` も使えます。
- キーは `oidc:s:<セッションID>` で、`oidc_session_timeout` を TTL とした `SETEX` で書き込みます。ログアウト通知から引けるように `oidc:x:sid:<sid>` と `oidc:x:sub:<sub>` のセット（同じ TTL）も維持します。書き込みと一括削除は 1 往復で済むよう `EVAL` の Lua スクリプトで行います。
- 応答は 1 回の読み取りで収まる必要があります。ID トークンが大きい IdP では `oidc_redis_buffer_size` を増やしてください。
- Redis に接続できない場合、セッションは「無効」として扱われ再認証になります（フェイルクローズ）。

#### Redis Sentinel

```nginx
http {
    oidc_session_store  redis;
    oidc_redis_sentinel 127.0.0.1:26379 127.0.0.1:26380 127.0.0.1:26381;
    oidc_redis_master   mymaster;
    ...
    location = /_oidc_redis {
        internal;
        # タイムアウトやバッファのためにダミーの宛先が必要（実際の宛先は Sentinel が返す）
        oidc_redis_pass 127.0.0.1:6379;
    }
}
```

マスターのアドレスは `SENTINEL get-master-addr-by-name` で解決し、ワーカーごとにキャッシュします。コマンドが失敗すると次の Sentinel に問い合わせ直すため、フェイルオーバー後は自動的に新しいマスターへ切り替わります。

#### Redis Cluster

```nginx
http {
    oidc_session_store  redis;
    oidc_redis_cluster  on;
    ...
    location = /_oidc_redis {
        internal;
        oidc_redis_pass 127.0.0.1:7000;   # 種となるノード
    }
}
```

キーの CRC16 から slot を求めてノードを選び、`MOVED` / `ASK` の応答でスロットマップを学習します（`ASK` の場合は `ASKING` を前置します）。クラスタでは 3 つのキーが別々の slot に落ちるため、`EVAL` の Lua スクリプトではなくキーごとのコマンド（`SETEX` / `SADD` / `EXPIRE`、削除は `SMEMBERS` + `DEL`）に切り替わります。`oidc_redis_cluster` と `oidc_redis_sentinel` は同時に指定できません。

### 内部ロケーション

本モジュールは非同期サブリクエストで IdP と通信するため、以下の内部ロケーションを定義する必要があります。`proxy_pass` には必ず下表の変数を使ってください（URL の出所を Discovery の結果に限定するための SSRF 対策です）。

| ロケーション | 必須の設定 |
|------------|-----------|
| `/_oidc_discovery` | `proxy_pass $oidc_discovery_url;` |
| `/_oidc_token` | `proxy_pass $oidc_token_url;` + `proxy_method POST;` + `proxy_set_body $oidc_token_body;` + `Authorization: $oidc_token_basic` |
| `/_oidc_jwks` | `proxy_pass $oidc_jwks_url;` |
| `/_oidc_userinfo` | `proxy_pass $oidc_userinfo_url;` + `Authorization: $oidc_userinfo_bearer`（`oidc_use_userinfo on` 時のみ） |
| `/_oidc_introspect` | `proxy_pass $oidc_introspect_url;` + `proxy_method POST;` + `proxy_set_body $oidc_introspect_body;` + `Authorization: $oidc_token_basic`（`oidc_introspection on` 時のみ） |
| `/_oidc_par` | `proxy_pass $oidc_par_url;` + `proxy_method POST;` + `proxy_set_body $oidc_par_body;` + `Authorization: $oidc_token_basic`（PAR を使う場合のみ） |
| `/_oidc_redis` | `oidc_redis_pass <addr>;`（`oidc_session_store redis` 時のみ） |

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
| `$oidc_sid` | ID トークンの `sid` クレーム（IdP 側セッション ID） |
| `$oidc_discovery_url` | Discovery URL（`/_oidc_discovery` 用） |
| `$oidc_token_url` | トークンエンドポイント URL（`/_oidc_token` 用） |
| `$oidc_jwks_url` | JWKS URL（`/_oidc_jwks` 用） |
| `$oidc_userinfo_url` | UserInfo URL（`/_oidc_userinfo` 用） |
| `$oidc_token_body` | トークンリクエストのボディ（`proxy_set_body` 用） |
| `$oidc_token_basic` | `Basic base64(client_id:client_secret)`（`Authorization` ヘッダ用） |
| `$oidc_userinfo_bearer` | `Bearer <access_token>`（`oidc_dpop on` のときは `DPoP <access_token>`。`Authorization` ヘッダ用） |
| `$oidc_introspect_url` | イントロスペクションエンドポイント URL（`/_oidc_introspect` 用） |
| `$oidc_introspect_body` | イントロスペクションリクエストのボディ（`proxy_set_body` 用） |
| `$oidc_par_url` | PAR エンドポイント URL（`/_oidc_par` 用） |
| `$oidc_par_body` | PAR リクエストのボディ（`proxy_set_body` 用） |
| `$oidc_dpop_proof` | 内部サブリクエスト（トークン / UserInfo）に添える DPoP proof |
| `$oidc_dpop_backend_proof` | バックエンドへ転送するための DPoP proof。`htu` は `oidc_dpop_htu`、`htm` はリクエストメソッド |
| `$oidc_token_type` | トークンタイプ（`Bearer` / `DPoP`）。ストアモードでのみ継続リクエストでも参照可能 |

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

### ログアウト通知（Back-Channel / Front-Channel）

IdP 側でログアウトしたときに RP のセッションも破棄するための仕組みです。いずれも `oidc_session_store` が必要です（Cookie モードでは 501 を返します）。

**Back-Channel Logout**: IdP が `oidc_backchannel_logout_uri` に `logout_token` を POST します。モジュールは JWKS で署名を検証したうえで、`iss` / `aud` / `iat`（300 秒以内）/ `events` に backchannel-logout イベントがあること / `nonce` が無いこと / `sub` か `sid` があること、を確認してから該当セッションをすべて破棄し 200 を返します。検証に失敗した場合は 400 です。

**Front-Channel Logout**: IdP が `oidc_frontchannel_logout_uri` を hidden iframe で読み込みます。Cookie は `SameSite=Lax` のため第三者コンテキストでは送られてこないので、クエリの `sid` でセッションを特定します。`iss` が付いていればプロバイダと一致することも確認します。

どちらのエンドポイントも認証を要求しません。IdP 側にも登録が必要です。

```nginx
oidc_backchannel_logout_uri  "https://app.example.com/backchannel-logout";
oidc_frontchannel_logout_uri "https://app.example.com/frontchannel-logout";
```

### クライアント認証

| `oidc_client_auth` | 送り方 |
|---|---|
| `basic`（既定） | `Authorization: Basic base64(client_id:client_secret)` |
| `post` | ボディに `client_id` と `client_secret` |
| `client_secret_jwt` | `client_secret` を鍵に HS256 で署名した client assertion（RFC 7523） |
| `private_key_jwt` | `oidc_client_jwt_key` の秘密鍵で RS256 署名した client assertion |
| `mtls` | クライアント証明書（RFC 8705 `tls_client_auth` / `self_signed_tls_client_auth`）。ボディには `client_id` だけを載せる |

client assertion の `aud` はトークンエンドポイントの URL、`exp` は 60 秒後、`jti` は毎回ランダムです。アルゴリズムは `oidc_client_jwt_alg` で変更できます（RS/PS/ES/HS の各 256/384/512）。

```nginx
oidc_client_auth    private_key_jwt;
oidc_client_jwt_key /etc/nginx/oidc-client.key;   # PEM 秘密鍵
oidc_client_jwt_kid "my-key-1";                   # 任意
```

#### mTLS（RFC 8705）

証明書はモジュールではなく `proxy_ssl_certificate` で送ります。`client_secret` は不要です。

```nginx
oidc_client_auth mtls;

location = /_oidc_token {
    internal;
    proxy_pass                  $oidc_token_url;
    proxy_method                POST;
    proxy_set_header            Content-Type "application/x-www-form-urlencoded";
    proxy_set_body              $oidc_token_body;
    proxy_ssl_certificate       /etc/nginx/oidc-client.crt;
    proxy_ssl_certificate_key   /etc/nginx/oidc-client.key;
    proxy_ssl_trusted_certificate /etc/nginx/idp-ca.crt;
    proxy_ssl_verify            on;
    proxy_ssl_server_name       on;
}
```

Discovery の `mtls_endpoint_aliases` にトークンエンドポイントやイントロスペクションエンドポイントのエイリアスがある場合は、そちらを使います（RFC 8705 5 章）。

### PAR（RFC 9126）

`oidc_par on` にすると、認可リクエストのパラメータを先にバックチャネルで PAR エンドポイントへ POST し、ブラウザには `client_id` と `request_uri` だけを渡します。`oidc_par` を書かなかった場合は Discovery の `require_pushed_authorization_requests` に従います（`pushed_authorization_request_endpoint` が無ければ通常の認可リクエストにフォールバック）。

```nginx
oidc_par on;

location = /_oidc_par {
    internal;
    proxy_pass       $oidc_par_url;
    proxy_method     POST;
    proxy_set_header Content-Type  "application/x-www-form-urlencoded";
    proxy_set_header Authorization $oidc_token_basic;
    proxy_set_body   $oidc_par_body;
}
```

### DPoP（RFC 9449）

`oidc_dpop on` と `oidc_dpop_key` で、トークンエンドポイントと UserInfo へのリクエストに proof を添えます。トークンが `token_type: DPoP` で返れば `Authorization` も `DPoP <token>` になり、`ath`（アクセストークンのハッシュ）付きの proof を送ります。

```nginx
oidc_dpop     on;
oidc_dpop_key /etc/nginx/oidc-dpop.key;           # EC 秘密鍵（P-256 など）
oidc_dpop_htu "https://api.example.com$uri";      # バックエンド向け proof の htu

location / {
    auth_oidc on;
    proxy_pass       http://backend;
    proxy_set_header Authorization "$oidc_token_type $oidc_access_token";
    proxy_set_header DPoP          $oidc_dpop_backend_proof;
}
```

鍵の JWK（`kty` / `crv` / `x` / `y`）は起動時に秘密鍵から導出し、すべての proof のヘッダに載せます。`jti` は毎回ランダム、`iat` は現在時刻です。バックエンド向けの proof はアクセストークンを保持している必要があるため、`oidc_session_store` が前提になります。

### 名前付きプロバイダ（`oidc_provider` ブロック）

NGINX Plus の設定に合わせて、http レベルでプロバイダをまとめて定義できます。

```nginx
http {
    oidc_provider keycloak {
        issuer        "https://idp.example.com/realms/myrealm";
        client_id     "my-client";
        client_secret "secret";
        redirect_uri  "https://app.example.com/callback";
        scope         "openid profile email";
        userinfo      on;
    }

    server {
        location / {
            auth_oidc keycloak;
            proxy_pass http://backend;
        }
    }
}
```

ブロック内で使える名前は `issuer` `client_id` `client_secret` `redirect_uri` `scope` `userinfo` `session_timeout` `logout_uri` `post_logout_redirect_uri` `client_auth` `auth_request_args` です。ロケーション側で同じ項目を設定した場合はロケーションの値が優先されます。

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
- **リフレッシュトークンの保管**: リフレッシュトークンはサーバー側のセッションにのみ保持し、Cookie には出さない
- **ログアウトトークンの検証**: Back-Channel Logout のトークンは JWKS で署名を検証し、`iss` / `aud` / `iat` / `events` / `nonce` 不在まで確認する
- **`private_key_jwt`**: `client_secret` を送らずに済むため、シークレットの配布が不要になる
- **DPoP**: proof は EC 鍵で署名し、`htm` / `htu` / `iat` / `jti` と（アクセストークンがある場合は）`ath` を載せる。秘密鍵はディスク上の PEM のみで、Cookie にもセッションにも出ない
- **PAR**: 認可パラメータはバックチャネルで送るため、`state` や `code_challenge` がブラウザの履歴やリファラに残らない
- **mTLS**: `client_secret` を持たずに済む。証明書と鍵は `proxy_ssl_certificate` で NGINX が扱うため、モジュールがメモリ上に保持しない
- **失効の検知**: `oidc_introspection on` でアクセストークンの失効を検知しセッションを破棄する。イントロスペクションエンドポイントに到達できない場合はセッションを維持し（フェイルオープン）警告ログを出す。タイムスタンプを更新しないため次のリクエストで再試行する

## テスト

`test/` に実モジュールを対象とした Playwright E2E テストがあります。

```bash
cd test && npm install && npx playwright install chromium
NGINX_SRC=/path/to/nginx-1.26.2 ./test/run-e2e.sh
```

`run-e2e.sh` はモジュールのビルド、Redis（単体 / Sentinel / 3 ノードクラスタ）とモック IdP 3 台（RS256 / ES256 / mTLS）の起動、NGINX の起動、Playwright の実行、後片付けまでを行い、**共有メモリ / Redis / Redis Sentinel / Redis Cluster / Cookie の 5 通り**でテストします（`redis-server`・`redis-cli`・`openssl` が必要）。詳細は [TEST_PLAYWRIGHT.md](TEST_PLAYWRIGHT.md) を参照してください。

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
19. `client_secret_jwt` / `private_key_jwt` によるクライアント認証
20. `oidc_provider` ブロックを参照するロケーション
21. Back-Channel Logout（署名不正・`nonce` 付きトークンの拒否を含む）
22. Front-Channel Logout
23. PAR による認可リクエストの事前送信（`request_uri` でのリダイレクト）
24. DPoP による鍵バインド（proof の検証・`token_type: DPoP`・バックエンド向け proof）
25. mTLS でのクライアント認証

## 実装状況

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | 完了 |
| Phase 2 | OIDC Discovery（非同期サブリクエスト・issuer 検証） | 完了 |
| Phase 3 | 認証フロー・トークン交換・PKCE・state 検証 | 完了 |
| Phase 4 | ID トークンの署名検証・クレーム検証・セッション Cookie | 完了 |
| Phase 5 | UserInfo・任意クレーム永続化・SSRF 対策・実モジュール E2E | 完了 |
| Phase 6 | サーバーサイドセッション・ログアウト・リフレッシュ・イントロスペクション | 完了 |
| Phase 7 | Redis セッションストア・Back/Front-Channel Logout・JWT クライアント認証・`oidc_provider` ブロック | 完了 |
| Phase 8 | PAR・DPoP・mTLS クライアント認証・Redis Sentinel / Cluster | 完了 |

### 既知の制限

| 項目 | 内容 |
|------|------|
| Redis Cluster のスロットマップ | 起動時に `CLUSTER SLOTS` を取得せず、`MOVED` / `ASK` の応答から学習する。最初の数リクエストは 1 往復多くなる |
| Redis Cluster のノード数 | ワーカーごとに最大 64 ノードまで記憶する |
| Cookie モードでの DPoP | アクセストークンを保持しないため、継続リクエストでは `$oidc_token_type` と `$oidc_dpop_backend_proof` が空になる |
| フロントチャネル系の Cookie | `SameSite=Lax` のため、Front-Channel Logout は `sid` クエリでのみセッションを特定する |
