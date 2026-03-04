# Phase 3 テスト項目（要手動確認）

サンドボックス環境の制約により、自動テストスクリプトでのE2Eの動作確認が困難なため、以下の項目について手動または結合テスト環境での確認をお願いします。

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
   - IdPからリダイレクトされてくるコールバックURI（例: `/callback?code=xxx`）にアクセスした際、内部で正しくインターセプトされること。

3. **トークン取得サブリクエストの実行**
   - コールバックエンドポイントで受け取った `code` を用い、NGINXが `/_oidc_token`（トークンエンドポイント用内部ロケーション）へサブリクエストを行うこと。
   - NGINXのデバッグログに `OIDC: Successfully retrieved tokens` が出力されること（トークン取得のJSONパース成功）。

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

        # 略
    }
}
```
