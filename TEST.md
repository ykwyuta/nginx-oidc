# Phase 3 テスト項目（要手動確認）

サンドボックス環境の制約により、自動テストスクリプトでのE2Eの動作確認が困難なため、以下の項目について手動または結合テスト環境での確認をお願いします。

## モジュールのビルド方法

NGINXソースコードが展開されている環境（例: `/usr/share/nginx/src`）で、以下のコマンドを実行し動的モジュールとしてコンパイルします。

```bash
# 依存ライブラリのインストール (Ubuntu/Debian系の場合)
sudo apt-get update
sudo apt-get install -y nginx-dev libjansson-dev libssl-dev

# NGINXソースディレクトリに移動し、モジュールを追加してコンパイル
cd /usr/share/nginx/src
sudo ./configure --with-compat --add-dynamic-module=/app
sudo make -f objs/Makefile modules

# コンパイルされた .so ファイルを現在のディレクトリへコピー
cp objs/ngx_http_oidc_module.so /app/
```

## 確認項目

1. **未認証ユーザーのリダイレクト**
   - 未認証状態で保護されたリソース（例: `/`）にアクセスした際、`302 Found` でIdPの認可エンドポイントにリダイレクトされること。
   - リダイレクトURLに以下のパラメータが正しく付与されていること：
     - `response_type=code`
     - `scope=openid`
     - `client_id` (設定値)
     - `redirect_uri` (設定値)
     - `state`
     - `nonce`

2. **コールバックエンドポイントの処理**
   - IdPからリダイレクトされてくるコールバックURI（例: `/callback?code=xxx&state=yyy`）にアクセスした際、内部で正しくインターセプトされること。
   - `code` や `state` が欠落している場合や、`state` が `oidc_state` Cookie の値と一致しない場合は `400 Bad Request` または `403 Forbidden` となること。

3. **トークン取得サブリクエストの実行**
   - コールバックエンドポイントで受け取った `code` を用い、NGINXが `/_oidc_token`（トークンエンドポイント用内部ロケーション）へサブリクエストを行うこと。
   - NGINXのデバッグログに `OIDC: Successfully retrieved tokens` が出力されること（トークン取得のJSONパース成功）。

4. **Phase 4 JWT署名検証・セッション発行（追加確認事項）**
   - サンドボックス環境では外部のIdPとの疎通が制限されているため、以下の動作確認はE2Eテスト環境（またはモックIdPを使用する環境）で人間による確認が必要です。
   - `/_oidc_jwks` へサブリクエストが発行され、メタデータから取得した `jwks_uri` 経由で公開鍵が正しく取得されること。
   - `id_token` の署名が `libjwt` を通じて正常に検証され、有効期限（`exp`）や `nonce`（Cookie に保持された値）が一致すること。
   - 認証成功後、`Set-Cookie` ヘッダにて `oidc_auth=` から始まるHMAC署名付きのセッションCookieが発行されること。
   - クレーム変数（`$oidc_claim_sub`, `$oidc_claim_email`, `$oidc_claim_name`）が正しくエクスポートされ、バックエンドへのリクエスト時にヘッダ等として利用できること。

## テスト時のNGINX設定例

```nginx
http {
    # 略
    server {
        listen 8080;

        # 保護されたリソース
        location / {
            auth_oidc "on";
            oidc_provider "http://127.0.0.1:8080/mock_idp";
            oidc_client_id "test_client";
            oidc_client_secret "test_secret";
            oidc_redirect_uri "/callback";

            # プロキシ先など
        }

        # トークン取得用内部ロケーション（proxy_pass等でPOSTボディを生成する設定が必要）
        location = /_oidc_token {
            internal;
            proxy_pass http://127.0.0.1:8080/mock_idp/token;
            proxy_set_header Content-Type "application/x-www-form-urlencoded";
            proxy_set_body $args;
            proxy_method POST;
        }

        # JWKS取得用内部ロケーション
        location = /_oidc_jwks {
            internal;
            proxy_pass http://127.0.0.1:8080/mock_idp/certs;
            proxy_method GET;
        }

        # 略
    }
}
```
