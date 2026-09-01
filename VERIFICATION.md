# 実装状況の検証レポート

本ドキュメントは `ngx_http_oidc_module` を**実際にビルドして動かして**検証した結果と、
そこで判明した問題への対処をまとめたものである。

- 初回検証: 2026-09-01（対象コミット `0f0719a`）— 致命的欠陥 3 件を含む 16 件を検出
- 修正後の再検証: 2026-09-01 — 検出した全件を修正し、実モジュールに対する E2E 8 シナリオが通過
- 追加機能の実装後: 2026-09-01 — 未実装として残っていた機能を実装し、E2E 14 シナリオ（ストアモード）/ 11 シナリオ（Cookie モード）が通過
- 残機能の実装後: 2026-09-01 — Redis ストア・Back/Front-Channel Logout・JWT クライアント認証・`oidc_provider` ブロックを実装し、E2E 21 シナリオが共有メモリ / Redis の両モードで通過（Cookie モードは 14 通過・7 スキップ）

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

## 4. 追加機能の実装

初回検証で「未実装」として整理していた機能をすべて実装した。

| 機能 | 実装内容 |
|------|---------|
| **サーバーサイドセッション** | `oidc_session_store <size>` で共有メモリゾーンを作成し、rbtree + LRU キューでセッションを保持する。Cookie は 256 bit のセッション ID のみを持つ。満杯時は期限切れ、次いで LRU 末尾から追い出す。ID トークン・アクセストークン・リフレッシュトークンを保持できるようになり、以下の 3 機能の前提となる |
| **RP-Initiated Logout** | `oidc_logout_uri` / `oidc_post_logout_redirect_uri` を追加。セッションと Cookie を破棄し、Discovery の `end_session_endpoint` へ `client_id`・`id_token_hint`・`post_logout_redirect_uri` を付けてリダイレクトする。`end_session_endpoint` が無い IdP ではローカルセッションのみ破棄 |
| **リフレッシュトークン** | `oidc_refresh_token on` で、アクセストークンの失効時に `grant_type=refresh_token` で更新する。新しい ID トークンが返れば署名と `iss`/`aud`/`exp` に加え `sub` の一致を検証する（`nonce` は認可リクエストのものなので検証しない）。更新に失敗した場合はセッションを破棄して通常の再認証にフォールバックする。Cookie の Max-Age も更新する |
| **Token Introspection** | `oidc_introspection on` / `oidc_introspection_interval` で RFC 7662 の失効確認を行う。`active: false` ならセッションを破棄。エンドポイントに到達できない場合はフェイルオープンし、確認時刻を更新しないため次のリクエストで再試行する |
| **`client_secret_post`** | `oidc_client_auth basic\|post` を追加。post のときは `client_secret` をボディに入れる（`client_id` は常にボディにあるため二重に送らない） |
| **`$oidc_id_token`** | ID トークンを変数として公開。ストアモードでは継続リクエストでも利用可能 |
| **`oidc_auth_request_args`** | 認可リクエストへの追加パラメータ。complex value なので `login_hint=$arg_login_hint` のように変数も使える |

### 追加機能の検証

`test/run-e2e.sh` はストアあり・なしの両構成でテストを実行する。

```
==> running the Playwright tests (session mode: store)
  14 passed
==> running the Playwright tests (session mode: cookie)
  3 skipped
  11 passed
```

追加したシナリオ:

| シナリオ | 検証する機能 |
|---------|-------------|
| `oidc_auth_request_args` の `prompt` / `login_hint` が認可 URL に付く | `oidc_auth_request_args` |
| モック IdP が post 方式のクライアント認証を受け取る | `client_secret_post` |
| ログイン後の通常リクエストで ID トークンが取り出せる | `$oidc_id_token` + ストア |
| `expires_in=1` のトークン失効後、更新後の ID トークン由来のクレームになる | リフレッシュトークン |
| IdP 側で失効させたアクセストークンが検出され再認証になる | Token Introspection |
| `end_session_endpoint` 経由で `post_logout_redirect_uri` に戻り、セッションが消える | RP-Initiated Logout |

手動での追加確認:

- 4 ワーカー構成で、同一セッションが全ワーカーから参照できること（共有メモリの検証）
- リフレッシュが発生したレスポンスに、更新後の Max-Age を持つ `Set-Cookie` が付くこと
- ログアウトの `Location` に `client_id` / `id_token_hint` / `post_logout_redirect_uri` が含まれること
- アクセスログ・エラーログに `client_secret` / `code_verifier` / トークン類が残らないこと（0 件）、`[alert]` / `[crit]` が 0 件であること

## 5. 残機能の実装

| 機能 | 実装内容 |
|------|---------|
| **Redis セッションストア** | `oidc_session_store redis;` と `/_oidc_redis` ロケーション（`oidc_redis_pass`）を追加。NGINX の upstream フレームワーク上に最小の RESP クライアントを実装した（`ngx_http_memcached_module` と同じ作り）。セッションの読み書きが非同期になるため、アクセスハンドラは `NGX_AGAIN` で待機し、完了ハンドラが `ctx->redis_after` に従って続き（ログイン完了 / ログアウトの 302 / リフレッシュ後の再開 / 単なる再開）を実行する。保存とログアウト時の一括削除は `EVAL` の Lua スクリプトで 1 往復にまとめ、配列応答のパースを不要にした。AUTH / SELECT にも対応 |
| **Back-Channel Logout** | `oidc_backchannel_logout_uri` を追加。POST ボディの `logout_token` を JWKS で検証し、OIDC Back-Channel Logout 1.0 2.6 の条件（`iss` / `aud` / `iat` 300 秒以内 / `events` に backchannel-logout / `nonce` 不在 / `sub` か `sid` あり）を確認してから該当セッションを破棄し 200 を返す |
| **Front-Channel Logout** | `oidc_frontchannel_logout_uri` を追加。iframe から呼ばれ Cookie が届かない前提で、クエリの `sid`（と任意の `iss`）だけでセッションを特定する |
| **`client_secret_jwt` / `private_key_jwt`** | `oidc_client_auth` に 2 つの方式を追加し、`oidc_client_jwt_key` / `oidc_client_jwt_kid` / `oidc_client_jwt_alg` を新設。libjwt で RFC 7523 の client assertion を組み立てる |
| **`oidc_provider` ブロック** | http レベルの `oidc_provider <name> { issuer ...; client_id ...; }` と `auth_oidc <name>;` を追加（NGINX Plus 互換）。引数が URL の場合は従来の `oidc_provider <url>;` として扱い、後方互換を保つ |

セッションを引くために `sub` と ID トークンの `sid` クレームを保持する必要が生じたため、共有メモリのエントリと Redis のレコードを共通のシリアライズ形式に統一し、ログアウト通知からの検索は共有メモリでは LRU の線形走査、Redis では `oidc:x:sid:` / `oidc:x:sub:` の集合で行うようにした。

### 実装中に判明した問題

| 問題 | 対処 |
|------|------|
| `nginx -t` が segfault | `ngx_http_upstream_hide_headers_hash()` を `hide_headers` が `NGX_CONF_UNSET_PTR` でない状態で呼んでいた。memcached モジュールと同じくこの呼び出し自体が不要だったため削除 |
| `oidc_provider` ブロックの名前が壊れる | `ngx_conf_parse()` がブロックを解析する間に `cf->args` が使い回されるため、名前を解析前に控えるよう修正 |
| `private_key_jwt` が HS256 で署名されていた | アルゴリズムの既定値をマージ時に書き込んでいたため、親の `client_secret_basic` 由来の HS256 が子ロケーションに継承されていた。既定値の決定をリクエスト時に移動 |
| Redis の応答ごとに 5 秒待たされる | `ngx_http_upstream_process_headers()` が `u->length` を -1 に戻すため、`process_header` で設定した長さが失われ読み取りタイムアウトまで終わらなかった。memcached と同じく `input_filter_init` で設定するよう修正 |
| Front-Channel Logout が 400 | `ngx_http_arg()` はパーセントエンコードされたままの値を返すため、`iss` を復号してから比較するよう修正 |

### 再検証

```
==> running the Playwright tests (session mode: store)
  21 passed
==> running the Playwright tests (session mode: redis)
  21 passed
==> running the Playwright tests (session mode: cookie)
  7 skipped
  14 passed
```

`-Werror` を含む既定のフラグでビルド警告ゼロ。アクセスログ・エラーログに `client_secret` / `code_verifier` / トークン類の出現は 0 件、`[alert]` / `[crit]` / `upstream timed out` も 0 件。

## 6. 残タスク

| 機能 | 説明 |
|------|------|
| Redis Sentinel / Cluster | 宛先は単一（または `upstream` ブロック）。フェイルオーバーは NGINX の upstream 機能に委ねている |
| Pushed Authorization Requests (PAR) / DPoP | 認可リクエストの事前送信、トークンの所有証明 |
| mTLS クライアント認証 | `tls_client_auth` / `self_signed_tls_client_auth` |
