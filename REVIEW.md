# nginx-oidc モジュール コードレビュー

## 概要

`ngx_http_oidc_module` は、NGINX Open Source に OpenID Connect (OIDC) 認証機能を追加する C 言語製のダイナミックモジュールです。通常 NGINX Plus 限定の OIDC 連携を、OSS 版でも実現することを目的としています。

外部ライブラリとして **Jansson**（JSON パース）と **OpenSSL**（将来の JWT 署名検証用）に依存しています。

---

## データ構造

```
ngx_http_oidc_loc_conf_t   ← nginx.conf のディレクティブ設定値
ngx_http_oidc_ctx_t        ← リクエストごとの状態管理
ngx_http_oidc_provider_metadata_t  ← IdP ディスカバリで取得したエンドポイント情報
```

- **`loc_conf`** は設定ファイル読み込み時に確定し、ワーカープロセス間で共有されます。
- **`ctx`** はリクエストプールに確保され、リクエストが終わると解放されます。
- **`metadata`** は `ctx` 内に保持されますが、**リクエストをまたいで共有されない**点が設計上の大きな問題です（後述）。

---

## 処理の全体フロー

```
[NGINX 起動]
    │
    └─ ngx_http_oidc_init()
         └─ ACCESS_PHASE に ngx_http_oidc_access_handler を登録

[HTTPリクエスト受信]
    │
    └─ ngx_http_oidc_access_handler()          # メインハンドラ
         │
         ├─ auth_oidc が "off" または未設定 → NGX_DECLINED（素通り）
         ├─ サブリクエスト自身 (r != r->main) → NGX_DECLINED（ループ防止）
         │
         ├─ [ctx 生成または取得]
         │
         ├─ ctx->metadata が NULL の場合
         │    ├─ discovery_attempted フラグが立っている → 500 エラー（失敗済み）
         │    └─ ngx_http_oidc_start_discovery()
         │         ├─ /_oidc_discovery?url=<provider>/.well-known/openid-configuration
         │         │  へサブリクエスト発行
         │         └─ NGX_AGAIN を返す（非同期待機）
         │              │
         │              └─ ngx_http_oidc_discovery_handler()  # サブリクエスト完了コールバック
         │                   ├─ HTTP ステータス確認
         │                   ├─ レスポンスボディ取得
         │                   └─ ngx_http_oidc_parse_discovery_json()
         │                        └─ authorization_endpoint / token_endpoint / jwks_uri を抽出
         │                           → ctx->metadata に格納
         │
         └─ ctx->metadata が非 NULL の場合
              │
              ├─ URI が redirect_uri と一致する場合（IdP からのコールバック）
              │    ├─ token_attempted フラグが立っている → NGX_DECLINED（ループ回避）
              │    ├─ クエリパラメータから code を取得
              │    └─ ngx_http_oidc_start_token_request()
              │         ├─ code, client_id, client_secret, redirect_uri を URL エンコード
              │         ├─ /_oidc_token へサブリクエスト発行（POST ボディとして渡す）
              │         └─ NGX_AGAIN を返す（非同期待機）
              │              │
              │              └─ ngx_http_oidc_token_handler()  # サブリクエスト完了コールバック
              │                   ├─ JSON をパースして id_token / access_token の存在確認
              │                   ├─ (Phase 4 未実装) JWT 検証・Cookie 設定
              │                   └─ r->parent->write_event_handler = ngx_http_core_run_phases
              │                      で親リクエストを再開
              │
              └─ コールバック以外のパス
                   ├─ Cookie ヘッダを走査して "oidc_auth=" の存在確認
                   ├─ Cookie あり → NGX_DECLINED（認証済みとして素通り）
                   └─ Cookie なし → ngx_http_oidc_redirect_to_idp()
                        ├─ authorization_endpoint に以下のパラメータを付加
                        │   response_type=code, scope=openid, client_id,
                        │   redirect_uri, state, nonce
                        └─ 302 リダイレクトを返す
```

---

## 改善点

以下に、セキュリティ・設計・実装の観点から問題点を整理します。

### 🔴 重大（セキュリティ）

#### 1. state / nonce がハードコードされている

```c
// ngx_http_oidc_redirect_to_idp(), L416-417
ngx_str_t state = ngx_string("random_state_123");
ngx_str_t nonce = ngx_string("random_nonce_123");
```

`state` はCSRF攻撃対策、`nonce` はリプレイ攻撃対策として使われる値です。固定値では意味をなしません。リクエストごとに暗号論的乱数（例: `RAND_bytes` from OpenSSL）で生成し、セッションと紐付けて検証する必要があります。

#### 2. 認証チェックが Cookie の存在確認のみ

```c
// ngx_http_oidc_access_handler(), L559
if (ngx_strnstr(header[i].value.data, "oidc_auth=", header[i].value.len)) {
    authenticated = 1;
```

`oidc_auth=` という文字列が Cookie に含まれているかを見るだけで、値の検証がありません。ブラウザから `Cookie: oidc_auth=anything` を送るだけで認証をバイパスできます。実装では、署名付きセッショントークンを発行し、サーバー側で検証する必要があります。

#### 3. Phase 4（JWT 検証）が未実装

```c
// ngx_http_oidc_token_handler(), L301-302
/* In Phase 4 we will validate this token and set a cookie.
 * For now, just assume success. */
```

`id_token` の JWT 署名検証・有効期限チェック・`nonce` 検証が行われていません。現状では IdP から返ってきた任意のトークンをそのまま信頼してしまいます。`jwks_uri` から鍵を取得して検証するロジックが必須です。

---

### 🟠 重要（設計上の問題）

#### 4. メタデータがリクエストをまたいで共有されない

```c
// ctx はリクエストプール (r->pool) に確保される
ctx->metadata = ngx_pcalloc(r->parent->pool, sizeof(...));
```

OIDC ディスカバリ結果はプロバイダが変わらない限り不変です。しかし現状では**リクエストごとに毎回ディスカバリを行い**、リクエスト終了時にメタデータが破棄されます。共有メモリゾーン（`ngx_shared_memory_add`）やワーカープロセスレベルのキャッシュに格納すべきです。

#### 5. redirect_uri の比較がパス部分のみ

```c
// ngx_http_oidc_access_handler(), L515-516
if (conf->redirect_uri.len > 0 && r->uri.len >= conf->redirect_uri.len &&
    ngx_strncmp(r->uri.data, conf->redirect_uri.data, conf->redirect_uri.len) == 0) {
```

`redirect_uri` に `http://example.com/callback` のようなフルURLが設定されると、`r->uri`（パスのみ）との比較が常に不一致になります。設定値からパス部分のみを抽出するか、ドキュメントでパスのみ指定するよう明記すべきです。

#### 6. auth_oidc のオン/オフ判定が脆弱

```c
// ngx_http_oidc_access_handler(), L483
if (conf->auth_oidc.len == 0 || ngx_strncmp(conf->auth_oidc.data, "off", 3) == 0) {
```

`"off"` のみ無効扱いで、`"on"` 以外の任意の値（例: `"enabled"`, `"yes"`）が設定されても有効と判定されます。NGINX 標準の `ngx_flag_t` と `ngx_conf_set_flag_slot` を使うことで、`on`/`off` のみを受け付ける型安全な実装にできます。

#### 7. トークンリクエストの引数がクエリパラメータとして渡されている

```c
// ngx_http_oidc_start_token_request(), L399
ngx_http_subrequest(r, &token_uri, &token_args, &sr, psr, NGX_HTTP_SUBREQUEST_IN_MEMORY)
```

`token_args` はクエリストリングとして内部 location の `/_oidc_token` に渡されていますが、OAuth 2.0 トークンエンドポイントへは `application/x-www-form-urlencoded` の POST ボディとして送るのが仕様です。サブリクエストでクエリパラメータを内部ロケーションに渡し、その nginx.conf 設定側でボディに変換する構成になっているとすれば明記が必要です。

---

### 🟡 軽微（コード品質）

#### 8. `ngx_http_oidc_parse_discovery_json` のメモリプール割り当てが不整合

```c
// L152-156
metadata->authorization_endpoint.data = ngx_palloc(r->pool, ...);
```

`metadata` 自体は `r->parent->pool` に確保（L78）されているのに、その中身のデータは `r->pool`（サブリクエストのプール）に確保されています。サブリクエスト終了時にデータが解放され、親リクエストから dangling pointer になる可能性があります。データも `r->parent->pool` に確保すべきです。

#### 9. Cookie パース処理が手書きで不完全

```c
// L557-563
if (header[i].key.len == sizeof("Cookie") - 1 && ...)
    if (ngx_strnstr(header[i].value.data, "oidc_auth=", header[i].value.len)) {
```

`ngx_strnstr` による部分文字列検索のため、`not_oidc_auth=value` のような Cookie 名にも誤ってマッチします。NGINX が提供する `ngx_http_parse_multi_header_lines` 等を利用するか、Cookie 名の境界を正確に確認する処理が必要です。

#### 10. ディスカバリ失敗時にリトライ不可

```c
// L502-505
if (ctx->discovery_attempted) {
    ngx_log_error(..., "OIDC: Discovery failed previously");
    return NGX_HTTP_INTERNAL_SERVER_ERROR;
}
```

一度失敗すると次のリクエストでも 500 を返し続けます（`ctx` はリクエストごとに新規生成されるため、実際には毎リクエストでリトライするのですが、コードの意図と挙動が乖離しています）。メタデータキャッシュを正しく実装した上で、失敗時のバックオフ戦略を検討してください。

#### 11. `ngx_http_oidc_discovery_handler` でエラー時も `NGX_OK` を返す分岐がある

JSON パース失敗時に `NGX_OK` を返しているため、`ctx->metadata` が NULL のまま後続処理が進み、`ngx_http_oidc_redirect_to_idp` で `auth_endpoint->len == 0` チェックに引っかかって 500 になります。エラーを明示的に伝播させる設計（`NGX_ERROR` を返し、呼び出し元でハンドリング）の方が意図が明確です。

---

## 実装フェーズの現状まとめ

| フェーズ | 内容 | 状態 |
|---------|------|------|
| Phase 1 | ディレクティブ定義・設定パース | ✅ 完了 |
| Phase 2 | OIDC Discovery（非同期 HTTP） | ✅ 完了 |
| Phase 3 | 認証フロー・トークン交換 | ✅ 完了（ただし上記の問題あり） |
| Phase 4 | JWT 署名検証・Cookie 発行 | ❌ 未実装 |
| Phase 5 | テスト・最適化・共有メモリキャッシュ | ❌ 未実装 |

---

## まとめ

コードの全体的な構造は NGINX モジュールとして適切で、非同期処理（サブリクエスト + コールバック）の設計も NGINX の作法に沿っています。しかし、**現状では本番環境での使用は推奨できません**。最低限、以下の対応が必要です。

1. `state` / `nonce` のランダム生成と検証
2. JWT 署名検証（Phase 4 の実装）
3. Cookie の署名・検証によるセッション管理
4. メタデータの共有メモリキャッシュ化
5. メモリプール割り当ての不整合修正（`r->pool` vs `r->parent->pool`）
