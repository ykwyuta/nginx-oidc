# Playwright を用いた E2E テスト実行手順

本ドキュメントは、NGINX OIDC モジュールに対する Playwright を使ったエンドツーエンド (E2E) テストの実行手順を説明します。テストは**実際にビルドしたダイナミックモジュール**を読み込んだ NGINX に対して実行します。モジュールの挙動を別実装で模したモックサーバーは使いません。

## 1. 前提条件

* **Node.js** (v18 以降)
* **npm**
* **NGINX のソース**（`--with-compat --add-dynamic-module=` でモジュールをビルドするため）
* **依存ライブラリ**: `libssl-dev`, `libjansson-dev`, `libjwt-dev`

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
4. モック IdP を 2 台起動
   * ポート 3000: RS256 で署名（クライアント `test-client-id`）
   * ポート 3001: ES256 で署名（クライアント `tenant-b-client`）
5. NGINX を起動（8080 が保護対象、8081 がクレームを返すバックエンド）
6. `npx playwright test` を **2 回** 実行する
   * `store`: `oidc_session_store` を有効にした構成
   * `cookie`: `oidc_session_store` を無効にした構成（クレームを Cookie に載せる）
7. 失敗時は `nginx` と IdP のログを表示し、最後に必ず後片付け

セッションストアを前提とする機能（`$oidc_id_token` の継続利用、リフレッシュ、イントロスペクション）のテストは `cookie` モードではスキップされます。

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

シナリオ 4・5・7 のために、モック IdP は次のテスト用フラグを持ちます。

* 認可リクエストに `bad_sig=1` を付けると、JWKS に載せていない鍵で ID トークンを署名する
* 認可リクエストに `bad_aud=1` を付けると、`aud` を別のクライアント ID にする
* 認可リクエストに `short_token=1` を付けると、`expires_in=1` のアクセストークンを発行する
* `MOCK_IDP_ALG=ES256` で EC 鍵による署名に切り替える
* `POST /test/revoke` で発行済みのアクセストークンをすべて失効させる（イントロスペクションが `active: false` を返すようになる）
* リフレッシュで発行した ID トークンは `name` を `Test User (refreshed)` にするため、更新が起きたことをテストから判別できる
* ID トークンに `token_auth` クレーム（`basic` / `post`）を入れ、使われたクライアント認証方式を判別できる

モック IdP のトークンエンドポイントは `client_secret_basic` のみを受け付け、クエリパラメータが付いたリクエストを 400 で拒否します。これにより、認可コードや `client_secret` が URL に載っていないことがテストで担保されます。

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
| `test/mock-idp.js` | モック OpenID Provider（RS256 / ES256、client_secret_basic、PKCE 検証） |
| `test/nginx.conf` | テスト用 NGINX 設定（保護対象・短命セッション・別プロバイダ・ログアウト/更新/失効確認・バックエンド） |
| `test/playwright.config.js` | Playwright 設定 |
| `test/package.json` | Node.js 依存パッケージ |
