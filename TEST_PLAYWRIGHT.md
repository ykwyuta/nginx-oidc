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

テストを実行するためには、**Mock IdP**と**NGINXサーバー**をバックグラウンドで立ち上げた上で、Playwrightを実行する必要があります。

### Step 1: Mock IdPの起動

`test/` ディレクトリにて、Node.jsでMock IdPを起動します。デフォルトでポート `3000` を使用します。

```bash
# /app/test ディレクトリで実行
node mock-idp.js > idp.log 2>&1 &
```

### Step 2: NGINXサーバーの起動

テスト用の設定ファイル `test/nginx.conf` を用いて、NGINXを起動します。デフォルトでポート `8080` を使用します。

```bash
# /app ディレクトリから実行
sudo /usr/sbin/nginx -c /app/test/nginx.conf -p /app > nginx.log 2>&1 &
```

### Step 3: Playwrightテストの実行

すべてのサーバーが立ち上がったら、Playwrightスクリプトを実行してブラウザテストを開始します。

```bash
# /app/test ディレクトリで実行
npx playwright test
```

テストの実行状況を見る場合は、UIモードやデバッグモードも利用可能です。
```bash
npx playwright test --ui
```

### Step 4: サーバーの停止（テスト終了後）

テストが終わったら、バックグラウンドで起動しているプロセスを終了させてください。

```bash
# Mock IdPを停止
kill $(lsof -t -i :3000)

# NGINXを停止
sudo killall nginx
```

---

## 4. 既知の問題 (Known Issues)

現在、Playwrightを用いたE2Eテストは**タイムアウトにより失敗（Fail）**する状態が確認されています。

### 原因の概要
OIDCのコールバック処理において、NGINXモジュールからIdPの `/token` エンドポイントに対するサブリクエストが、**なぜか2回連続して送信されてしまう**という事象が発生しています。

1. Playwrightがブラウザ上でログインを完了し、NGINXの `/callback?code=xxxx...` にリダイレクトされる。
2. NGINXのアクセスフェーズ（`ngx_http_oidc_access_handler`）がトークン取得のサブリクエストをキックする。
3. Mock IdPに1回目のトークン要求（POST `/token`）が到達し、Mock IdPは正常にコードを消費してトークンを返却する。
4. 直後に、NGINXから全く同じ `code` を使った2回目のトークン要求（POST `/token`）が送信される。
5. Mock IdP側ではすでに1回目のリクエストでその `code` を削除（消費）しているため、2回目のリクエストに対して `400 Bad Request (invalid_grant)` を返す。
6. このサブリクエストの失敗により、NGINXは正しくセッションを発行できず、ブラウザ側へのレスポンスが滞り、結果的にPlaywrightのテストがタイムアウト（30秒超過）エラーとなる。

### 今後の課題
NGINXのCモジュール側の実装において、非同期サブリクエストを発行した後にフェーズが中断（`NGX_AGAIN`）され、再度アクセスフェーズが呼ばれた際（あるいはイベントループの別のフックで）に、多重にサブリクエストが発行されている（無限ループに近い状態）可能性があります。
テストをパスさせるためには、C言語側の `ngx_http_oidc_module.c` 内での `ctx->token_attempted` フラグの処理や、サブリクエストの完了ハンドリングを修正する必要があります。