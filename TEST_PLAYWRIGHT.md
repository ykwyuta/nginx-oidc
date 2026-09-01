# Playwright を用いた E2E テスト実行手順

本ドキュメントは、NGINX OIDC モジュールに対する Playwright を使ったエンドツーエンド (E2E) テストの実行手順を説明します。テストは**実際にビルドしたダイナミックモジュール**を読み込んだ NGINX に対して実行します。モジュールの挙動を別実装で模したモックサーバーは使いません。

## 1. 前提条件

* **Node.js** (v18 以降)
* **npm**
* **NGINX のソース**（`--with-compat --add-dynamic-module=` でモジュールをビルドするため）
* **依存ライブラリ**: `libssl-dev`, `libjansson-dev`, `libjwt-dev`
* **redis-server** と **redis-cli**（Redis ストア・Sentinel・クラスタのテスト用。`redis-sentinel` は `redis-server --sentinel` で代用）
* **openssl** コマンド（`private_key_jwt` / DPoP / mTLS 用の鍵と証明書の生成）

```bash
apt-get install libssl-dev libjansson-dev libjwt-dev
```

## 2. セットアップ

```bash
cd test
npm install
npx playwright install chromium
```

## 3. 実行

```bash
# リポジトリのルートで
NGINX_SRC=/path/to/nginx-1.26.2 ./test/run-e2e.sh
```

`run-e2e.sh` が以下を順に行います。

1. `NGINX_SRC` でモジュールと nginx をビルド
2. 作業ディレクトリ `test/.e2e` に prefix を作成し、`test/nginx.conf` の `load_module` をビルド結果のパスに差し替え
3. `nginx -t` で設定を検証
4. 鍵と証明書を生成する
   * `private_key_jwt` 用の RSA 鍵ペア
   * DPoP 用の EC 鍵（P-256）
   * mTLS 用の CA・IdP サーバー証明書・クライアント証明書（CN は `test-client-id`）
5. Redis を 3 通りの構成で起動する
   * 単体: ポート 6399
   * Sentinel: ポート 26399（`oidc-test` として 6399 を監視、quorum 1）
   * クラスタ: ポート 7000 / 7001 / 7002 の 3 マスター（`redis-cli --cluster create --cluster-yes`）
6. モック IdP を 3 台起動
   * ポート 3000: RS256 で署名（クライアント `test-client-id`）
   * ポート 3001: ES256 で署名（クライアント `tenant-b-client`）
   * ポート 3002: HTTPS + `requestCert`（mTLS クライアント認証用）
7. NGINX を起動（8080 が保護対象、8081 がクレームを返すバックエンド）
8. `npx playwright test` を **5 回** 実行する
   * `store`: `oidc_session_store 4m;`（共有メモリ）
   * `redis`: `oidc_session_store redis;`
   * `sentinel`: `oidc_redis_sentinel 127.0.0.1:26399;` + `oidc_redis_master oidc-test;`
   * `cluster`: `oidc_redis_cluster on;` + `oidc_redis_pass 127.0.0.1:7000;`
   * `cookie`: `oidc_session_store` を無効にした構成（クレームを Cookie に載せる）
9. 失敗時は `nginx` / IdP / Redis / Sentinel のログを表示し、最後に必ず後片付け

サーバー側ストアを前提とする機能（`$oidc_id_token` の継続利用、リフレッシュ、イントロスペクション、Back/Front-Channel Logout、DPoP の `token_type` とバックエンド向け proof）のテストは `cookie` モードではスキップされます。

ビルド済みのバイナリを使う場合は `NGINX_SRC` の代わりに以下を指定します。

```bash
NGINX_BIN=/usr/sbin/nginx \
OIDC_MODULE=/etc/nginx/modules/ngx_http_oidc_module.so \
MIME_TYPES=/etc/nginx/mime.types \
./test/run-e2e.sh
```

Chromium が Playwright の既定の場所にない場合は `PLAYWRIGHT_CHROMIUM_PATH` で実行ファイルを指定できます。

## 4. テストシナリオ（test/e2e.spec.js）

| # | シナリオ | 確認内容 |
|---|---------|---------|
| 1 | ログインとクレームの引き渡し | 未認証アクセスが IdP へリダイレクトされること（`response_type` / `client_id` / `state` / `nonce` / `code_challenge_method=S256` / 絶対 `redirect_uri`）、ログイン後に元 URL へ戻り 200 になること、`sub` / `email` / `name` / `groups` / `tenant_id` がバックエンドに渡ること、UserInfo が**配列**で返す `groups` が `admin,user` に展開されること、セッション Cookie だけで別パスにアクセスできること、セッション Cookie の追加クレームが `groups` と `tenant_id` のみでプロトコルクレームを含まないこと |
| 2 | セッション Cookie の改竄 | HMAC 部分を書き換えた Cookie では認証済みと見なされず IdP へ差し戻されること |
| 3 | state 不一致 | `state` がクッキーと一致しないコールバックが 403 になること |
| 4 | 不正な署名 | JWKS に載っていない鍵で署名した ID トークンが 401 で拒否されること |
| 5 | 不正な aud | `aud` が別クライアントの ID トークンが 401 で拒否されること |
| 6 | セッション有効期限 | `oidc_session_timeout 1s` のロケーションで、経過後に再認証となること |
| 7 | 複数プロバイダ | `/tenant-b/` が別ポート・別クライアント・ES256 の IdP を使うこと、`oidc_claims groups` により `tenant_id` が取り込まれないこと |
| 8 | コールバックパス | `/callback-not-really` がコールバックとして扱われず、通常の未認証アクセスになること |
| 9 | 追加パラメータ | `oidc_auth_request_args` の `prompt` と `login_hint` が認可リクエストに付くこと |
| 10 | client_secret_post | `oidc_client_auth post` のロケーションで、モック IdP が post 方式の認証を受け取ること |
| 11 | `$oidc_id_token` | ストアモードで、ログイン後の通常リクエストでも ID トークンが取り出せること |
| 12 | リフレッシュ | `expires_in=1` のアクセストークンが失効した後のリクエストで、リフレッシュトークンによる更新が行われ、更新後の ID トークン由来のクレームになること |
| 13 | イントロスペクション | IdP 側でアクセストークンを失効させると、`oidc_introspection_interval` 経過後のリクエストでセッションが破棄され再認証になること |
| 14 | ログアウト | `/session/logout` が IdP の `end_session_endpoint` を経由して `post_logout_redirect_uri` へ戻り、セッション Cookie が消え、再度ログインを求められること |
| 15 | client_secret_jwt | `/csjwt/` のログインで、モック IdP が HS256 の client assertion を検証できること |
| 16 | private_key_jwt | `/pkjwt/` のログインで、モック IdP が RSA 公開鍵で client assertion を検証できること |
| 17 | プロバイダブロック | `auth_oidc test-idp;` のロケーションが、ブロックの `client_id` / `redirect_uri` / `userinfo` を継承すること |
| 18 | Back-Channel Logout | ログイン後に `sid` 宛の logout token を POST すると 200 が返り、セッションが消えること |
| 19 | 不正な logout token | JWKS にない鍵で署名した logout token が 400 で拒否されること |
| 20 | nonce 付き logout token | `nonce` を含む logout token が 400 で拒否されること |
| 21 | Front-Channel Logout | `iss` と `sid` 付きの GET で 200 が返り、セッションが消えること |
| 22 | PAR | `/par/` のログインで、認可リクエストのクエリが `client_id` と `request_uri` だけになり、モック IdP が事前登録したパラメータでフローを完了できること |
| 23 | DPoP | `/dpop/` のログインで、モック IdP がトークン要求と UserInfo 要求の proof を検証できること、`token_type` が `DPoP` になること、バックエンド向け proof のヘッダが `typ: dpop+jwt` と `jwk`（`kty: EC` / `crv: P-256`）を持つこと |
| 24 | mTLS | `/mtls/` のログインで、HTTPS のモック IdP がクライアント証明書の CN で認証を行うこと（`token_auth` が `mtls`） |

シナリオ 4・5・7 のために、モック IdP は次のテスト用フラグを持ちます。

* 認可リクエストに `bad_sig=1` を付けると、JWKS に載せていない鍵で ID トークンを署名する
* 認可リクエストに `bad_aud=1` を付けると、`aud` を別のクライアント ID にする
* 認可リクエストに `short_token=1` を付けると、`expires_in=1` のアクセストークンを発行する
* `MOCK_IDP_ALG=ES256` で EC 鍵による署名に切り替える
* `POST /test/revoke` で発行済みのアクセストークンをすべて失効させる（イントロスペクションが `active: false` を返すようになる）
* リフレッシュで発行した ID トークンは `name` を `Test User (refreshed)` にするため、更新が起きたことをテストから判別できる
* ID トークンに `token_auth` クレーム（`basic` / `post` / `client_secret_jwt` / `private_key_jwt` / `mtls`）を入れ、使われたクライアント認証方式を判別できる
* ID トークンに `sid` クレームを入れ、ログアウト通知の対象をテストから指定できる
* `GET /test/logout_token?sid=...&sub=...&nonce=...&bad_sig=1` で Back-Channel Logout 用のトークンを発行する
* `MOCK_IDP_CLIENT_PUBKEY` に公開鍵のパスを渡すと `private_key_jwt` を検証する
* `POST /par` で `request_uri` を発行し、認可リクエストが `request_uri` だけで来た場合に保存済みのパラメータを使う
* `DPoP` ヘッダの proof を検証し（`typ` / `htm` / `htu` / `jwk`、アクセストークンがあれば `ath`）、成功したら `token_type: DPoP` でトークンを返す
* `MOCK_IDP_TLS_CERT` / `MOCK_IDP_TLS_KEY` / `MOCK_IDP_TLS_CA` を渡すと HTTPS + クライアント証明書要求で起動する

モック IdP のトークンエンドポイントはクエリパラメータが付いたリクエストを 400 で拒否します。これにより、認可コードや `client_secret` が URL に載っていないことがテストで担保されます。

## 5. 手動でサーバーを起動する場合

```bash
# IdP
cd test && node mock-idp.js &

# NGINX（prefix と load_module のパスは環境に合わせる）
nginx -p /path/to/prefix -c /path/to/nginx.conf

# テスト
cd test && npx playwright test
```

## 6. ファイル構成

| ファイル | 説明 |
|---|---|
| `test/run-e2e.sh` | ビルドから後片付けまでを行うテストランナー |
| `test/e2e.spec.js` | Playwright の E2E テスト |
| `test/mock-idp.js` | モック OpenID Provider（RS256 / ES256、5 種のクライアント認証、PKCE 検証、PAR、DPoP、mTLS） |
| `test/nginx.conf` | テスト用 NGINX 設定（保護対象・短命セッション・別プロバイダ・ログアウト/更新/失効確認・JWT クライアント認証・プロバイダブロック・PAR・DPoP・mTLS・バックエンド） |
| `test/playwright.config.js` | Playwright 設定 |
| `test/package.json` | Node.js 依存パッケージ |
