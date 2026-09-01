# 実装状況の検証レポートと残タスク

本ドキュメントは `README.md` / `REVIEW.md` に記載された実装状況を、**実際にビルドして動かして**
検証した結果をまとめたものである。ソースコードの読解だけでなく、NGINX 実機と Mock IdP を用いた
E2E 実行、および libjwt の挙動確認プログラムによって裏付けを取っている。

検証日: 2026-09-01 / 対象コミット: `0f0719a`

---

## 1. 検証環境と手順

| 項目 | 内容 |
|------|------|
| NGINX | 1.26.2（ソースから `--with-compat --add-dynamic-module=` でビルド。debug 版も別途作成） |
| libjwt | 1.17.0（Ubuntu 24.04 `libjwt-dev`） |
| Jansson | 2.14 |
| OpenSSL | 3.0.13 |
| IdP | `test/mock-idp.js`（RS256 署名、Discovery / token / certs / userinfo 提供） |
| テスト | `test/e2e.spec.js`（Playwright + Chromium）および curl による手動フロー再現 |

実行した手順:

1. `./configure --with-compat --add-dynamic-module=<repo> && make modules`
2. `test/nginx.conf` をそのまま使い、実 NGINX + `ngx_http_oidc_module.so` を起動
3. Playwright E2E（`TEST_PLAYWRIGHT.md` の「方法A」）を実行
4. 同じフローを curl で 1 リクエストずつ再現し、Mock IdP 側に全リクエストログを出して突き合わせ
5. `--with-debug` ビルドの NGINX で `error_log ... debug;` を有効にし、サブリクエストとフェーズ遷移を追跡
6. libjwt の署名検証挙動を単体 C プログラムで確認
7. 参考として `TEST_PLAYWRIGHT.md` の「方法B」（`test/nginx_mock.js` = Node 製の疑似実装）でも E2E を実行

---

## 2. 検証結果サマリ

| 機能 | ドキュメントの記載 | 実測結果 |
|------|------------------|----------|
| モジュールのビルド | 完了 | **OK** — nginx 1.26.2 で `-Werror` を含む警告ゼロでビルド成功 |
| ディレクティブ定義・設定パース | 完了 | **OK** — `nginx -t` 成功、全ディレクティブが機能 |
| OIDC Discovery（非同期サブリクエスト） | 完了 | **OK** — メタデータ取得・キャッシュとも動作 |
| 認可リダイレクト（state/nonce/PKCE 生成、Cookie 発行） | 完了 | **OK** — 302 と 4 種の Cookie、`code_challenge_method=S256` を確認 |
| コールバックの state 検証 | 完了 | **OK** — 不一致時 403 |
| トークン交換 | 完了 | **一部** — リクエストは飛び id_token も取得できるが、後段が破綻（C-1） |
| JWKS 取得・JWT 署名検証 | 完了 | **NG** — 完了ハンドラの結果が使われる前にリクエストが 500 で終了（C-1）。加えて署名検証自体が無効化されている（C-2） |
| UserInfo エンドポイント | 完了 | **NG** — サブリクエストが IdP に到達しない（C-1） |
| セッション Cookie 発行・継続アクセスでのクレーム復元 | 完了 | **NG** — 上記により到達しない |
| E2E テストスイート | 完了 | **NG** — 実モジュールでは失敗。Node 製モック（`test/nginx_mock.js`）に対してのみ成功 |

**結論: 認証フローは実機では最後まで到達せず、`/callback` が必ず 500 で終了する。**
「Phase 1〜5 完了」「本番投入可能なレベル」という現行ドキュメントの記載は、実機の挙動と一致していない。

---

## 3. 致命的課題

### C-1. コールバック処理が完了せず、認証が成立しない（最優先）

**症状**: `/callback?code=...&state=...` が常に HTTP 500 を返す。ブラウザは元 URL に戻らない。

**再現**: `test/nginx.conf` そのままで Playwright E2E を実行すると、ログインフォーム送信後に
200 応答が返らずタイムアウトする（`oidc_use_userinfo off` にしても同じ）。

**原因**: NGINX は「サブリクエストが finalize されたタイミングで親リクエストを posted_requests に積み、
フェーズを再実行する」という動作をする。本モジュールはトークンサブリクエストの完了ハンドラ
（`ngx_http_oidc_token_handler`）の中から JWKS サブリクエストを新規に発行しているため、
**JWKS の応答を待たずに親リクエストのアクセスフェーズが再実行される**。
そのとき `ctx->token_attempted == 1` かつ `ctx->redirect_issued == 0` であるため、
`ngx_http_oidc_access_handler` の「ループ防止」ガード（`ngx_http_oidc_module.c:1706` 付近）が
`NGX_HTTP_INTERNAL_SERVER_ERROR` を返してリクエストを終わらせてしまう。

debug ビルドのログ（抜粋、時系列）:

```
http finalize request: 0, "/_oidc_token?code=...&client_secret=...&grant_type=authorization_code..."
OIDC: Successfully retrieved id_token
http subrequest "/_oidc_jwks?url=http://127.0.0.1:3000/certs"
http posted request: "/_oidc_jwks?url=http://127.0.0.1:3000/certs"
http posted request: "/callback?code=...&state=..."      <-- JWKS 完了前に親が再開
access phase: 6
http finalize request: 500, "/callback?code=...&state=..."   <-- ここで打ち切り
http special response: 500, "/callback?..."
```

Discovery だけが正常に動くのは、Discovery サブリクエストがアクセスハンドラ自身から発行されており
（親の finalize を経由しない）、親が再開する時点で `mcf->metadata` が埋まっているためである。
サブリクエストの完了ハンドラから次のサブリクエストを繋ぐ token→JWKS→UserInfo の連鎖だけが破綻する。

**修正方針**: `ngx_http_oidc_ctx_t` に「サブリクエスト実行中」を表すフラグ（例 `ctx->waiting` /
`ctx->done`）を持たせ、アクセスハンドラは処理中は `NGX_AGAIN`（または `NGX_DONE`）を返して待機し、
連鎖が完了して初めて 302 / エラーを確定させる。`ngx_http_auth_request_module` の
`ctx->done` パターンが参考になる。あわせて、`token_attempted` を「同一リクエスト内でのリトライ防止」
と「連鎖の完了判定」に兼用している現状の設計を分離する必要がある。

### C-2. ID トークンの署名が検証されていない（認証バイパスにつながる）

`ngx_http_oidc_module.c:726` は次のように libjwt を呼んでいる。

```c
/* libjwt >= 1.15.3 supports jwt_decode() with JWKS JSON directly */
int jwt_ret = jwt_decode(&jwt, (const char *)ctx->id_token.data,
                         (const unsigned char *)json_data, 0);
```

このコメントは誤りである。

* libjwt 1.x に **JWKS を扱う API は存在しない**（`/usr/include/jwt.h` に `jwks` 系のシンボルなし。
  JWKS 対応は libjwt 3.x の `jwt_verifier` / `jwks_*` API で追加された）。
* `jwt_decode()` の第 4 引数 `key_len` に `0` を渡すと、libjwt は「鍵なし」と解釈し
  **署名検証を一切行わない**。ヘッダのドキュメントにも
  "If no key is supplied, then a non-encrypted token will be parsed without any checks for a valid signature" と明記されている。

実測（libjwt 1.17.0、`alg=RS256`・署名部分をデタラメな文字列に差し替えたトークン）:

```
key_len=0   -> rc=0   (ACCEPTED - NO SIGNATURE CHECK)   sub=attacker email=evil@example.com
key_len=56  -> rc=22  (rejected)
```

つまり `TEST_PLAYWRIGHT.md` 5.2 の「`jwt_decode` の第4引数を 0 に変更（JWKS の JSON 文字列であることを
libjwt に通知）」という修正は、**EINVAL エラーを署名検証の無効化によって回避してしまっている**。
現状は「JWT のデコードのみ・署名は未検証」であり、`exp` と `nonce` だけがチェックされている。

**影響**: トークンエンドポイントの応答を差し替えられる攻撃者（後述 H-1 のとおり upstream の TLS 証明書
検証も行われていない）は、任意の `sub` / `email` を持つ ID トークンを通せる。

**修正方針**（いずれか）:

1. JWKS を Jansson でパースし、`kid` に一致する鍵の `n` / `e` から RSA 公開鍵を組み立てて PEM 化し、
   `jwt_decode()` に鍵長付きで渡す（libjwt 1.x のまま対応可能）。
2. `jwt_decode_2()` のキープロバイダを使い、`kid` に応じた鍵を返す。
3. libjwt 3.x に依存を上げ、`jwks_create()` + `jwt_verifier` を使う（`config` と README の依存記述も更新）。

いずれの場合も、`alg` の許可リスト（`none` と対称鍵アルゴリズムの拒否）を必ず実装すること。

### C-3. `iss` / `aud` クレームが検証されていない

`ngx_http_oidc_jwks_handler` が検証しているのは `exp` と `nonce` のみで、
`iss`（発行者が `oidc_provider` と一致するか）と `aud`（`client_id` を含むか）を見ていない。
OpenID Connect Core 3.1.3.7（ID Token Validation）で必須とされている検証であり、
他クライアント向けに発行されたトークンの転用を許してしまう。`iat` の妥当性チェックも無い。

---

## 4. 本番投入前に必要な課題（高）

### H-1. `proxy_pass $oidc_*_url` の運用上の前提が欠落している

* **`resolver` が必須**。変数を使った `proxy_pass` は起動時に upstream を解決できないため、
  IdP のエンドポイントがホスト名の場合 `resolver` ディレクティブが無いと実行時に失敗する。
  実測でも `no resolver defined to resolve localhost` で JWKS 取得が失敗した。
  `README.md` / `REVIEW.md` / `test/nginx.conf` のいずれにも `resolver` の記載が無い。
* **upstream の TLS 検証が無い**。`proxy_ssl_verify` は既定で off であり、
  `proxy_ssl_name` / `proxy_ssl_server_name` / `proxy_ssl_trusted_certificate` の指定も無い。
  HTTPS の IdP に対して証明書を検証していないため、C-2 と組み合わせると認証バイパスが成立する。
  設定例への追記、または `oidc_ssl_trusted_certificate` 相当の実装が必要。

### H-2. トークンエンドポイントへのパラメータ送信方法が実 IdP で通用しない

`test/nginx.conf` の `/_oidc_token` は `proxy_set_body $args;` と
`proxy_set_header Content-Length "";` を併用しているが、`Content-Length` を消すと本文を
受信側が解釈できない。Mock IdP 側のログでも本文は空で、`req.query` へのフォールバック
（`test/mock-idp.js:83`）によってかろうじて成立している。

さらに、サブリクエストの引数はそのまま upstream の URI に付くため、
**`client_secret` がリクエストラインに載り、NGINX の error_log と IdP のアクセスログに平文で残る**。
実測ログ:

```
upstream: "http://127.0.0.1:3000/token?code=...&client_id=test-client-id&client_secret=test-client-secret&..."
```

`client_secret_basic`（Authorization ヘッダ）または正しく `Content-Length` を伴う
`application/x-www-form-urlencoded` 本文での送信に改めるべき。

### H-3. セッションに有効期限が無い

`oidc_auth` Cookie のペイロードには timestamp を書き込んでいるが、
検証側（`ngx_http_oidc_module.c:1745` 付近）でこの値を一切参照していない。
Cookie 属性にも `Max-Age` / `Expires` が無い。結果として、
一度発行されたセッション Cookie は ID トークンの有効期限と無関係に、
ワーカーの HMAC シークレットが変わるまで無期限に有効となる。
`oidc_session_timeout`（仮）のようなディレクティブと timestamp 検証が必要。

### H-4. プロバイダのメタデータがワーカー単位のグローバル 1 個だけ

`ngx_http_oidc_main_conf_t` に `metadata` / `discovery_url` / `userinfo_url` を
1 組しか持たないため、複数の location で異なる `oidc_provider` を設定すると、
先に Discovery を実行した location の設定が全 location に適用される。
「複数プロバイダ未対応」は既知の未実装項目として挙げられているが、
実際には**誤設定が黙って通り、別 IdP のエンドポイントが使われる**ため、
最低限 location ごとにメタデータを保持するか、設定時に検出して警告する必要がある。

### H-5. E2E テストが実モジュールを検証していない

`test/nginx_mock.js` は「C モジュールの動作を Node で再現した」Express サーバーであり、
`ngx_http_oidc_module.so` を一切使わない。実測でも:

* `nginx_mock.js`（方法B）に対して: **1 passed**
* 実 NGINX + モジュール（方法A）に対して: **1 failed**（コールバックで 500 → タイムアウト）

現状のテストは「モックが自分自身をテストしている」状態であり、C-1 のような
モジュール本体の欠陥を検出できない。CI ではモジュールをビルドして方法A を実行すべきである。

---

## 5. 中程度の課題

| ID | 内容 |
|----|------|
| M-1 | 配列・真偽値・オブジェクトのクレームが無視される。`groups` を配列で返す IdP（Keycloak 既定、Azure AD 等）では取得できない。`TEST_PLAYWRIGHT.md` 5.4 は Mock IdP 側をカンマ区切り文字列に変更して回避しているだけで、モジュール側は未対応 |
| M-2 | JWT の全クレームを無差別に `extra_claims` へ格納しており、`nonce` / `at_hash` / `exp` / `iat` / `jti` などもセッション Cookie に載る。Cookie 肥大化（3500 バイト上限に早く到達）と不要な情報の外部保存につながる。転送するクレームを選択する仕組み（許可リスト）が望ましい |
| M-3 | コールバックパスの判定が前方一致（`ngx_http_oidc_module.c:1691` 付近）。`/callback-foo` や `/callback/x` もコールバックとして扱われる。完全一致にすべき |
| M-4 | `oidc_return_to` の検証が「先頭が `/`」のみ。`merge_slashes off;` の構成では `//evil.example.com` がプロトコル相対 URL としてオープンリダイレクトになりうる。2 文字目が `/` や `\` の場合を弾くべき |
| M-5 | Discovery の TTL 失効時、`mcf->metadata = NULL` にするだけで `ngx_cycle->pool` から確保した旧メタデータを解放しない。ワーカーの生存期間中、1 時間ごとにリークが蓄積する |
| M-6 | `test/nginx.conf` の保護 location が `proxy_pass http://127.0.0.1:8080/backend;` と自分自身へプロキシしている。テスト専用の構成であり、実運用の参考にはならない旨の注記が必要 |
| M-7 | `test/playwright.config.js` の Chromium パスが `/root/.cache/ms-playwright/chromium-1194/...` 決め打ちで、他環境では実行できない。`PLAYWRIGHT_BROWSERS_PATH` / 既定の解決に任せるべき |
| M-8 | 認証失敗時（JWT 不正・nonce 不一致・トークン取得失敗）の応答が一律 500。401/403 の使い分けと、IdP への再認証リダイレクトの検討が必要 |

---

## 6. 未実装機能（ドキュメント記載どおり・妥当）

以下は `README.md` / `REVIEW.md` の「未実装」記載と実装が一致していることを確認した。

* RP-Initiated Logout
* リフレッシュトークンによる自動更新
* Token Introspection
* 複数プロバイダ対応（ただし H-4 のとおり、誤設定が黙認される点は要対処）
* `oidc_ssl_trusted_certificate`（H-1 と関連）
* `$oidc_id_token` 変数 / `oidc_provider` ブロック構文 / `extra_auth_args` / `client_secret_post`

---

## 7. 残タスク一覧（推奨実施順）

| 順 | ID | タスク | 区分 |
|----|----|--------|------|
| 1 | C-1 | サブリクエスト連鎖中に親リクエストのフェーズが再実行される問題を修正し、コールバックを完走させる | 致命 |
| 2 | C-2 | JWKS から公開鍵を組み立てて ID トークンの署名を実際に検証する（`alg` 許可リストを含む） | 致命 |
| 3 | C-3 | `iss` / `aud`（必要に応じて `azp` / `iat`）の検証を追加 | 致命 |
| 4 | H-5 | 実モジュールを使う E2E（方法A）を通し、CI で実行する。方法B は補助に格下げ | 高 |
| 5 | H-2 | トークンリクエストを正しい POST 本文（または Basic 認証）に変更し、`client_secret` のログ露出を止める | 高 |
| 6 | H-1 | `resolver` と `proxy_ssl_*` の必須設定をドキュメント・テスト設定に追加（または専用ディレクティブを実装） | 高 |
| 7 | H-3 | セッション有効期限（timestamp 検証 + Cookie の Max-Age + ディレクティブ） | 高 |
| 8 | H-4 | location ごとのプロバイダメタデータ保持、または設定時の検出・警告 | 高 |
| 9 | M-1 | 配列クレーム（`groups` 等）のサポート | 中 |
| 10 | M-2 | セッション Cookie に載せるクレームの許可リスト化 | 中 |
| 11 | M-3, M-4 | コールバックパス完全一致・`oidc_return_to` の検証強化 | 中 |
| 12 | M-5 | Discovery 再取得時のメタデータ解放 | 中 |
| 13 | M-6, M-7 | テスト設定の整備（自己プロキシへの注記、Chromium パスの環境非依存化） | 中 |
| 14 | M-8 | 認証失敗時のステータスコード設計 | 中 |
| 15 | D-1 | `README.md` / `REVIEW.md` / `TEST_PLAYWRIGHT.md` の実装状況の記載を実測に合わせて修正（特に「JWT 署名検証: 完了」「Phase 4/5 完了」「E2E テスト実装済み」「本番投入可能」の各記載） | ドキュメント |
| 16 | — | RP-Initiated Logout 以降の未実装機能（従来の優先度どおり） | 機能追加 |
