# 実装状況の検証レポート

本ドキュメントは `ngx_http_oidc_module` を**実際にビルドして動かして**検証した結果と、
そこで判明した問題への対処をまとめたものである。

- 初回検証: 2026-09-01（対象コミット `0f0719a`）— 致命的欠陥 3 件を含む 16 件を検出
- 修正後の再検証: 2026-09-01 — 検出した全件を修正し、実モジュールに対する E2E 8 シナリオが通過

---

## 1. 検証環境と手順

| 項目 | 内容 |
|------|------|
| NGINX | 1.26.2（`--with-compat --add-dynamic-module=` でビルド。`--with-debug` 版も併用） |
| libjwt | 1.17.0 |
| Jansson | 2.14 |
| OpenSSL | 3.0.13 |
| IdP | `test/mock-idp.js`（RS256 / ES256、client_secret_basic、PKCE 検証） |
| テスト | `test/run-e2e.sh`（Playwright + Chromium）および curl による手動フロー再現 |

実施した手順:

1. モジュールと nginx をソースからビルド（`-Werror` で警告ゼロ）
2. `test/nginx.conf` で実 NGINX + `ngx_http_oidc_module.so` を起動し Playwright を実行
3. 同じフローを curl で 1 リクエストずつ再現し、IdP 側の全リクエストログと突き合わせ
4. `--with-debug` ビルドでサブリクエストとフェーズ遷移を追跡
5. libjwt の署名検証挙動を単体 C プログラムで確認
6. NGINX のアクセスログ・エラーログに秘密情報が残らないことを確認

---

## 2. 初回検証で判明した問題と対処

### 致命的

| ID | 問題 | 対処 |
|----|------|------|
| **C-1** | **コールバックが完了せず認証が成立しない。** `/callback` が常に 500。NGINX はサブリクエストが finalize されるたびに親のフェーズを再実行するが、モジュールはトークン完了ハンドラから JWKS サブリクエストを発行していたため、JWKS の応答を待たずに親が「ループ防止」ガードで 500 を返していた | `ctx->waiting` / `ctx->done` / `ctx->status` を導入。アクセスハンドラは連鎖の実行中は `NGX_AGAIN` を返して待機し、各段の完了時に `ngx_http_oidc_finish()` が結果を確定させる。さらに NGINX が同一サブリクエストを複数回 finalize することでハンドラが二重実行される問題（実測で JWKS ハンドラが 2 回実行され UserInfo サブリクエストが二重発行された）に対し、`*_handled` フラグで各完了ハンドラを冪等化した |
| **C-2** | **ID トークンの署名が検証されていない。** `jwt_decode(..., json_data, 0)` の第 4 引数 0 は「JWKS を渡す指定」ではなく「鍵なし＝検証しない」の意味（libjwt 1.x に JWKS API は存在しない）。署名をデタラメに差し替えた RS256 トークンが `rc=0` で受理されることを実測で確認 | JWKS の JWK から SubjectPublicKeyInfo (DER→PEM) を組み立て、その公開鍵で `jwt_decode()` を呼ぶよう変更。RSA (`n`/`e`) と EC (`crv`/`x`/`y`) に対応。`kid` の一致、`kty` と `alg` の整合、`use=sig` を確認し、`alg` は RS/PS/ES の 256/384/512 のみ許可（`none` と HS\* は拒否＝アルゴリズム混同攻撃対策）。DER は OpenSSL 1.1/3.x の API 差を避けるため自前で構築 |
| **C-3** | `iss` / `aud` が未検証（`exp` と `nonce` のみ） | `ngx_http_oidc_validate_claims()` を追加し、OIDC Core 3.1.3.7 に従って `iss` / `aud` / `azp` / `exp` / `iat` / `nonce` を検証（クロックスキュー ±60 秒）。Discovery 文書の `issuer` が `oidc_provider` と一致するかも検証（OIDC Discovery 4.3） |

### 高

| ID | 問題 | 対処 |
|----|------|------|
| **H-1** | 変数を使った `proxy_pass` に `resolver` が必要なことがどこにも書かれておらず、実測で `no resolver defined to resolve localhost` により JWKS 取得が失敗。upstream の TLS 検証（`proxy_ssl_verify`）も未設定 | README・REVIEW・`test/nginx.conf` に `resolver` の必要性と、`proxy_ssl_verify` / `proxy_ssl_trusted_certificate` / `proxy_ssl_server_name` を含む設定例を明記 |
| **H-2** | `client_secret` と認可コードが upstream のリクエストラインに載り、NGINX の error_log と IdP のアクセスログに平文で残る。さらに `proxy_set_header Content-Length "";` により POST ボディが IdP に届かず、モック IdP のクエリフォールバックで辛うじて成立していた | クライアント認証を `client_secret_basic` に変更し `$oidc_token_basic` で Authorization ヘッダとして送出。リクエストパラメータは `$oidc_token_body` + `proxy_set_body` でボディとして送り、サブリクエストには引数を渡さない。アクセストークンも `$oidc_userinfo_bearer` としてヘッダで渡す。`Content-Length ""` は設定例から削除し、書いてはいけない旨を明記 |
| **H-3** | セッション Cookie の timestamp を検証しておらず `Max-Age` も無いため、事実上無期限 | `oidc_session_timeout`（既定 1h）を追加。Cookie に `Max-Age` を付け、毎リクエスト発行時刻を検証する。未来日時の Cookie も拒否 |
| **H-4** | メタデータがワーカー単位でグローバル 1 組のみ。複数 location で別プロバイダを設定すると先勝ちで混線 | キャッシュをロケーション単位（`lcf->cache`）に変更。内部ロケーションへ渡す URL 群もリクエストコンテキストに移し、変数ハンドラは `r->main` の ctx を読む |
| **H-5** | E2E テストが `test/nginx_mock.js`（C モジュールを Node で再実装したもの）に対して実行されており、モジュール本体の欠陥を検出できない | `nginx_mock.js` を削除。`test/run-e2e.sh` を追加し、モジュールのビルド → モック IdP 2 台の起動 → NGINX 起動 → Playwright 実行 → 後片付けを一括で行う。テストは実モジュールのみを対象とする |

### 中

| ID | 問題 | 対処 |
|----|------|------|
| **M-1** | 配列・真偽値のクレームが無視され、`groups` を配列で返す IdP に対応できない | `ngx_http_oidc_claim_to_str()` で文字列・整数・実数・真偽値・配列（カンマ区切りに展開）に対応。モック IdP の UserInfo は `groups` を配列で返すようにし、`admin,user` に展開されることを E2E で検証 |
| **M-2** | JWT の全クレームを無差別にセッション Cookie へ格納し、`nonce` や `at_hash` まで載っていた | プロトコルクレーム 15 種と `sub`/`email`/`name` を除外。`oidc_claims` ディレクティブで許可リストも指定可能。E2E で Cookie の追加クレームが `groups` と `tenant_id` のみであることを検証 |
| **M-3** | コールバックパスの判定が前方一致で、`/callback-foo` もコールバック扱い | `redirect_uri` のパス部分を設定時に切り出し（`lcf->callback_path`）、完全一致で判定 |
| **M-4** | `oidc_return_to` の検証が「先頭が `/`」のみで、`//host` がオープンリダイレクトになりうる | 2 文字目が `/` や `\` の場合と、制御文字・非 ASCII を含む場合を拒否。Cookie に格納する際はパーセントエンコードする（`r->uri` は復号済みで Cookie 値に使えない文字を含みうるため） |
| **M-5** | Discovery 再取得時に旧メタデータを解放せず、1 時間ごとにリークが蓄積 | キャッシュを世代ごとの専用プールに確保し、再取得時に旧プールを解放。リクエストはメタデータのコピーをリクエストプールに持つため解放の影響を受けない |
| **M-6** | テスト設定が `proxy_pass http://127.0.0.1:8080/backend` と自分自身へプロキシしていた | バックエンドを 8081 の別 server ブロックに分離 |
| **M-7** | `playwright.config.js` の Chromium パスが決め打ちで他環境で実行できない | 既定の解決に任せ、必要なら `PLAYWRIGHT_CHROMIUM_PATH` で上書きする形に変更 |
| **M-8** | 認証失敗時の応答が一律 500 | IdP の `error` → 403、パラメータ欠落 → 400、`state` 不一致 → 403、ID トークン不正 → 401、IdP との通信・パース失敗 → 502、設定不備 → 500 に整理 |

### ドキュメント

| ID | 問題 | 対処 |
|----|------|------|
| **D-1** | README / REVIEW / TEST_PLAYWRIGHT の実装状況の記載が実測と乖離（「JWT 署名検証: 完了」「E2E テスト実装済み」「本番投入可能」など） | 3 ファイルとも現在の実装に合わせて全面改訂。運用上の必須設定（`resolver`、`proxy_ssl_verify`、`Content-Length` を消さないこと）も追記 |

---

## 3. 修正後の再検証

### ビルド

nginx 1.26.2 に対し `-Werror` を含む既定のフラグで警告ゼロでビルドできることを確認。

### E2E（実モジュール、8 シナリオすべて通過）

```
Running 8 tests using 1 worker
  8 passed (4.5s)
```

| # | シナリオ | 検証する修正 |
|---|---------|-------------|
| 1 | ログイン → クレーム引き渡し → セッション再利用 | C-1, M-1, M-2 |
| 2 | セッション Cookie の改竄 → 再認証 | — |
| 3 | `state` 不一致 → 403 | M-8 |
| 4 | JWKS にない鍵で署名した ID トークン → 401 | **C-2** |
| 5 | `aud` が別クライアント → 401 | **C-3** |
| 6 | `oidc_session_timeout` 経過後 → 再認証 | H-3 |
| 7 | 別ロケーションが別ポート・ES256 の IdP を使用 | H-4, C-2（EC 経路） |
| 8 | `/callback-not-really` はコールバック扱いしない | M-3 |

シナリオ 7 の IdP は ES256 で署名しており、EC 鍵の JWK→PEM 経路も実際に通っている。

### ログに秘密情報が残らないこと

E2E 実行後のアクセスログ・エラーログを検査し、`client_secret` / `code_verifier` / アクセストークンの出現が 0 件であることを確認。upstream として記録される URL も `http://127.0.0.1:3000/certs` のみ（トークンエンドポイントはボディ送信のためクエリを持たない）。

### 想定内のエラーログのみ

```
OIDC: the callback state does not match the cookie
OIDC: ID token signature verification failed (alg "RS256", kid "test-key-1")
OIDC: ID token aud does not contain oidc_client_id
```

いずれも意図的な不正リクエストに対するもの。`[alert]` / `[crit]` は 0 件。

---

## 4. 残タスク（未実装機能）

以下は初回検証時から「未実装」として整理されているもので、今回の修正対象外である。

| 優先度 | 機能 | 説明 |
|--------|------|------|
| P2 | RP-Initiated Logout | `end_session_endpoint` へのリダイレクト。シングルサインアウトに必要 |
| P3 | `client_secret_post` | `client_secret_basic` を受け付けない IdP への対応 |
| P3 | `$oidc_id_token` 変数 | ID トークンをそのままバックエンドへ渡す用途 |
| P3 | `extra_auth_args` | `login_hint` や `prompt=select_account` などの追加パラメータ |
| P4 | リフレッシュトークン | アクセストークンの自動更新 |
| P4 | Token Introspection | IdP への失効確認 |
| P4 | サーバーサイドセッション | スケールアウト時の失効管理 |
