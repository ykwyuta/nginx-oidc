# Playwrightを用いたE2Eテスト実行手順

本ドキュメントは、NGINX OIDCモジュールに対するPlaywrightを使用したエンドツーエンド（E2E）テストの実行手順を説明するものです。実際のブラウザ（Chromium）を操作し、Mock IdPと連携して認証フローが正常に動作するかを検証します。

## 1. 前提条件

テストを実行する環境には以下がインストールされている必要があります。

* **Node.js** (v18以降を推奨)
* **npm** (Node.jsに付属)
* **NGINX** (本モジュールを動的モジュールとしてビルド可能な環境)
* **必要な依存ライブラリ**: `nginx-dev`, `libjansson-dev`, `libssl-dev`, `libjwt-dev`

## 2. 環境構築

### 2.1 モジュールのビルド

まず、NGINX OIDCモジュール（`ngx_http_oidc_module.so`）をビルドし、テスト用NGINX設定から読み込める場所に配置します。

```bash
# NGINXソースディレクトリへ移動
cd /usr/share/nginx/src

# コンパイル
sudo ./configure --with-compat --add-dynamic-module=/app
sudo make -f objs/Makefile modules

# モジュールを現在のプロジェクト内にコピー
sudo mkdir -p /app/objs
sudo cp objs/ngx_http_oidc_module.so /app/objs/
```

### 2.2 テスト用依存パッケージのインストール

`test/` ディレクトリに移動し、Mock IdPとPlaywrightを動かすためのパッケージをインストールします。

```bash
cd /app/test
npm install

# Playwrightのブラウザバイナリ（Chromium）をインストール
npx playwright install chromium
```

## 3. テストの実行手順

テストを実行するためには、**Mock IdP** と **NGINXサーバー（または nginx_mock.js）** をバックグラウンドで立ち上げた上で、Playwrightを実行する必要があります。

実行方法は2通りあります。

---

### 方法A: 実際のNGINXを使ってテストを実行する（本番相当）

NGINXバイナリと動的モジュールを使って完全なE2Eテストを行います。

#### Step 1: Mock IdPの起動

`test/` ディレクトリにて、Node.jsでMock IdPを起動します。デフォルトでポート `3000` を使用します。

```bash
# /app/test ディレクトリで実行
node mock-idp.js > idp.log 2>&1 &
```

#### Step 2: NGINXサーバーの起動

テスト用の設定ファイル `test/nginx.conf` を用いて、NGINXを起動します。デフォルトでポート `8080` を使用します。

```bash
# /app ディレクトリから実行
sudo /usr/sbin/nginx -c /app/test/nginx.conf -p /app > nginx.log 2>&1 &
```

#### Step 3: Playwrightテストの実行

```bash
# /app/test ディレクトリで実行
npx playwright test
```

#### Step 4: サーバーの停止（テスト終了後）

```bash
# Mock IdPを停止
kill $(lsof -t -i :3000)

# NGINXを停止
sudo killall nginx
```

---

### 方法B: nginx_mock.jsを使ってテストを実行する（開発・デバッグ向け）

`test/nginx_mock.js` は、NGINXの動的モジュール（Cコード）が行うOIDC処理をNode.jsで再現したモックサーバーです。NGINXのビルドが不要なため、OIDCフローの動作確認やPlaywrightテストのデバッグに適しています。

`nginx_mock.js` は以下のNGINXモジュールの主要動作を再現しています：

- Cookie（`oidc_state`, `oidc_nonce`, `oidc_return_to`, `oidc_auth`）の生成・検証
- HMAC-SHA256によるCookie署名
- `/callback` でのトークン交換・JWT検証（簡易）・UserInfoリクエスト
- セッションCookie発行後の302リダイレクト（`redirect_issued` フラグ相当）
- 認証済みリクエストへのクレーム付与とJSONレスポンス

#### Step 1: Mock IdPの起動

```bash
# /app/test ディレクトリで実行
node mock-idp.js > idp.log 2>&1 &
```

#### Step 2: nginx_mock.jsの起動（ポート8080）

```bash
# /app/test ディレクトリで実行
node nginx_mock.js > nginx_mock.log 2>&1 &
```

#### Step 3: Playwrightテストの実行

```bash
# /app/test ディレクトリで実行
npx playwright test
```

テストの実行状況を見る場合は、UIモードやデバッグモードも利用可能です。

```bash
npx playwright test --ui
npx playwright test --debug
```

#### Step 4: サーバーの停止（テスト終了後）

```bash
# Mock IdPを停止
kill $(lsof -t -i :3000)

# nginx_mock.jsを停止
kill $(lsof -t -i :8080)
```

---

## 4. テストシナリオ（e2e.spec.js）

`test/e2e.spec.js` に定義されているテストは以下のフローを検証します：

1. ブラウザで `http://localhost:8080/protected-resource` にアクセスする
2. NGINXがMock IdP（`http://localhost:3000/auth`）へリダイレクトすることを確認する
3. リダイレクト先URLに `redirect_uri`, `state`, `nonce`, `client_id` パラメータが含まれることを確認する
4. ログインフォームに `testuser` / `password` を入力して送信する
5. 認証後、元のURLへリダイレクトされてHTTP 200が返ることを確認する
6. レスポンスJSONに以下のクレームが含まれることを確認する：
   - `sub`: `user-123`
   - `email`: `testuser@example.com`
   - `name`: `Test User`
   - `groups`: `admin,user`
   - `tenant_id`: `tenant-456`
7. セッションCookieが有効で、別パス（`/another-path`）へのアクセスでも同じクレームが返ることを確認する

---

## 5. 実装の変遷と解決済み課題

### 5.1 エラーパスでの無限ループ（解決済み）

**問題**: `ngx_http_oidc_token_handler` などのサブリクエストハンドラにおいて、エラーパスで親リクエストの再開（`r->parent->write_event_handler = ngx_http_core_run_phases`）が行われていなかったため、無限に `NGX_AGAIN` 状態となる問題があった。

**修正**: 各エラーパスに `r->parent->write_event_handler = ngx_http_core_run_phases` を追加し、エラー時に親リクエストのフェーズ処理を確実に再開するようにした。

### 5.2 JWT検証エラー（解決済み）

**問題**: `jwt_decode` 関数の呼び出しにおいて、JWKS（JSON形式）を渡す際のキー長パラメータ（第4引数）に `json_len` を渡していたため、エラー（errno 22: EINVAL）が発生していた。またJSONデータがヌル終端されていなかった。

**修正**: `jwt_decode` の第4引数を `0` に変更（JWKSのJSON文字列であることをlibjwtに通知）し、動的確保するJSONバッファを `json_len + 1` バイトに増やしてヌル終端するようにした。

### 5.3 "header already sent" エラーと二重レスポンス（解決済み）

**問題**: コールバック処理（`/callback`）でトークン交換後に `ngx_http_oidc_issue_session_and_redirect` が `Set-Cookie` / `Location` ヘッダを設定した後、アクセスフェーズが再び呼ばれると `proxy_pass` のコンテンツフェーズも実行されてしまい、NGINXエラーログに以下のアラートが出力されてテストがタイムアウトしていた。

```
[alert] ... header already sent while reading response header from upstream
```

**修正**: `ngx_http_oidc_ctx_t` に `redirect_issued` フラグを追加した。`ngx_http_oidc_issue_session_and_redirect` の末尾でこのフラグを `1` に設定し、アクセスハンドラ（`ngx_http_oidc_access_handler`）の `/callback` 処理パスの先頭で `redirect_issued` が立っている場合は即座に `NGX_HTTP_MOVED_TEMPORARILY` を返すようにした。これにより、コンテンツフェーズ（`proxy_pass`）へ処理が流れなくなった。

またこの修正に合わせて、トークン交換を試みたが `redirect_issued` が立っていないケース（JWTエラーなどで認証が成立しなかった場合）では `NGX_DECLINED` の代わりに `NGX_HTTP_INTERNAL_SERVER_ERROR` を返し、失敗した認証コールバックがバックエンドへ無言で転送されるのを防ぐようにした。

### 5.4 groupsクレームの型不一致（解決済み）

**問題**: `test/mock-idp.js` の `/userinfo` エンドポイントが `groups` をJSON配列（`["admin","user"]`）として返していたため、NGINXモジュールのUserInfoパーサーがこれを無視し（文字列・数値クレームのみを扱う実装のため）、Playwrightの `expect(body.groups).toBe('admin,user')` アサーションが失敗していた。

**修正**: `mock-idp.js` の `/userinfo` エンドポイントで `groups` をカンマ区切り文字列（`"admin,user"`）として返すよう変更した。

---

## 6. ファイル構成

| ファイル | 説明 |
|---|---|
| `test/e2e.spec.js` | PlaywrightのE2Eテストスクリプト |
| `test/mock-idp.js` | Mock OIDCプロバイダ（ポート3000） |
| `test/nginx_mock.js` | NGINXモジュールの動作をNode.jsで再現したモックサーバー（ポート8080、開発・デバッグ向け） |
| `test/nginx.conf` | 本番相当のNGINX設定（`ngx_http_oidc_module.so` を使用） |
| `test/playwright.config.js` | Playwrightの設定（Chromiumパス、タイムアウト） |
| `test/package.json` | Node.js依存パッケージの定義 |
| `ngx_http_oidc_module.c` | NGINXダイナミックモジュール本体 |
